"""Free cloud report jobs: GitHub OIDC, aggregate-only inference, durable results.

The worker cannot log in, read individual evidence, or change incident decisions.
Only the fixed main-branch workflow in the owner's public repository is trusted.
No database credential or reusable API key is given to GitHub.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from alba_security.governance import GovernanceAudit, audit
from alba_security.intelligence import IntelligenceReport, aggregate_period
from alba_security.llm import Narrative, write_narrative
from alba_security.models import utc_now
from alba_security.report_job import MonthlyReportRecord
from alba_security.reports import aggregate_month

REPOSITORY = 'hassanaliff-ai/browser-extension-'
REPOSITORY_ID = '1385178535'
OWNER_ID = '332855592'
WORKFLOW = REPOSITORY + '/.github/workflows/cloud-reports.yml@refs/heads/main'
ISSUER = 'https://token.actions.githubusercontent.com'
AUDIENCE = 'extsecure-cloud-reports'
JWKS_URL = ISSUER + '/.well-known/jwks'
MODEL = 'qwen2.5:7b-instruct-q4_K_M'
MODEL_DIGEST = '845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e'
AREA = 'cloud_reports'
ACTOR = 'system:github-reports'
BOOTSTRAP = 'cloud_reports_initialized'
KSA = timezone(timedelta(hours=3))
MAX_BATCH = 3
SAFE_STAGES = {'cloud_ai', 'validation', 'connection', 'generation'}


def enabled():
    return os.getenv('CLOUD_REPORT_AUTOMATION_ENABLED',
                     '1' if os.getenv('RENDER') == 'true' else '0') == '1'


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid encoding')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


class GitHubIdentity:
    """Bounded RS256 verification; never trust token-supplied key URLs."""
    def __init__(self):
        self.keys = {}
        self.expires = 0
        self.last_fetch = -60
        self.lock = threading.Lock()

    def _key(self, kid):
        with self.lock:
            if time.monotonic() >= self.expires:
                if time.monotonic() - self.last_fetch < 30:
                    if kid in self.keys:
                        return self.keys[kid]
                    raise ValueError('Signing key refresh is bounded')
                self.last_fetch = time.monotonic()
                with httpx.Client(timeout=8, follow_redirects=False, trust_env=False) as client:
                    response = client.get(JWKS_URL)
                    response.raise_for_status()
                    if len(response.content) > 65536:
                        raise ValueError('Key response too large')
                    result = response.json()
                keys = {}
                for row in result.get('keys', [])[:20]:
                    if row.get('kty') == 'RSA' and row.get('alg', 'RS256') == 'RS256':
                        n = int.from_bytes(_unb64(row['n']), 'big')
                        e = int.from_bytes(_unb64(row['e']), 'big')
                        if n.bit_length() >= 2048 and e == 65537:
                            keys[row['kid']] = rsa.RSAPublicNumbers(e, n).public_key()
                if not keys:
                    raise ValueError('No valid signing keys')
                self.keys, self.expires = keys, time.monotonic() + 900
            if kid not in self.keys:
                # Refresh on the next request to support rotation without an unbounded fetch loop.
                self.expires = 0
                raise ValueError('Unknown signing key')
            return self.keys[kid]

    def verify(self, token, *, now=None):
        if not isinstance(token, str) or len(token) > 20000:
            raise ValueError('Invalid identity')
        header_part, claims_part, signature = token.split('.')
        header, claims = json.loads(_unb64(header_part)), json.loads(_unb64(claims_part))
        if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
            raise ValueError('Invalid identity algorithm')
        self._key(header['kid']).verify(_unb64(signature),
            (header_part + '.' + claims_part).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
        current = int((now or utc_now()).timestamp())
        for name in ('exp', 'iat', 'nbf'):
            if type(claims.get(name)) is not int:
                raise ValueError('Missing identity time')
        if not (current - 60 <= claims['exp'] <= current + 660
                and current - 660 <= claims['iat'] <= current + 60
                and claims['nbf'] <= current + 60
                and 0 < claims['exp'] - claims['iat'] <= 660):
            raise ValueError('Expired identity')
        expected = {'iss': ISSUER, 'aud': AUDIENCE, 'repository': REPOSITORY,
                    'repository_id': REPOSITORY_ID, 'repository_owner_id': OWNER_ID,
                    'ref': 'refs/heads/main', 'workflow_ref': WORKFLOW,
                    'runner_environment': 'github-hosted', 'repository_visibility': 'public'}
        if any(claims.get(k) != v for k, v in expected.items()):
            raise ValueError('Untrusted workflow identity')
        if claims.get('event_name') not in {'schedule', 'workflow_dispatch', 'push'}:
            raise ValueError('Untrusted workflow event')
        if not re.fullmatch(r'\d{1,20}', str(claims.get('run_id', ''))):
            raise ValueError('Invalid workflow run')
        if not re.fullmatch(r'[a-f0-9]{40}', claims.get('sha', '')):
            raise ValueError('Invalid workflow revision')
        if claims.get('job_workflow_ref', WORKFLOW) != WORKFLOW:
            raise ValueError('Untrusted reusable workflow')
        return claims


IDENTITY = GitHubIdentity()


def _utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _last_week_end(now):
    current = _utc(now)
    end = current.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=(current.weekday()+1) % 7)
    return end - timedelta(days=7) if current < end + timedelta(hours=6) else end


def _last_month_end(now):
    current = _utc(now)
    end = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return (end-timedelta(days=1)).replace(day=1) if current < end+timedelta(hours=6) else end


def periods_due(now, initialized):
    """Bootstrap the latest complete week/month, then retain every missed period."""
    now, initialized = _utc(now), _utc(initialized)
    if initialized > now:
        raise ValueError('Invalid initialization clock')
    result = []
    end, last = _last_week_end(initialized), _last_week_end(now)
    while end <= last:
        start = end - timedelta(days=7)
        result.append(('weekly', start.date().isoformat(), start, end))
        end += timedelta(days=7)
    end, last = _last_month_end(initialized), _last_month_end(now)
    while end <= last:
        start = (end-timedelta(days=1)).replace(day=1)
        result.append(('monthly', start.strftime('%Y-%m'), start, end))
        end = (end+timedelta(days=32)).replace(day=1)
    return sorted(result, key=lambda r: r[3], reverse=True)


def _initialized(db, now):
    row = db.scalar(select(GovernanceAudit).where(GovernanceAudit.area == AREA,
        GovernanceAudit.action == BOOTSTRAP).order_by(GovernanceAudit.created_at, GovernanceAudit.id).limit(1))
    return _utc(row.created_at) if row else _utc(now)


def _existing(db, kind, period, language):
    return db.scalar(select(IntelligenceReport).where(IntelligenceReport.kind == kind,
        IntelligenceReport.period == period, IntelligenceReport.language == language))


def _snapshot(db, kind, start, end, *, manual=False):
    totals, archive = aggregate_period(db, start, end)
    monthly = None
    if kind == 'monthly':
        from alba_security.monthly_ml import analyze_month
        monthly = aggregate_month(db, start.year, start.month)
        monthly['machine_learning'] = analyze_month(db, start.year, start.month)
        ml = monthly['machine_learning']
        totals['machine_learning'] = {'status': ml['status'],
            'active_training_days': int(ml.get('active_training_days', 0)),
            'unusual_day_count': len(ml.get('unusual_days', []))}
    if kind == 'weekly' and not manual:
        totals['schedule'] = 'Sunday 09:00 Asia/Riyadh; Sunday–Saturday UTC coverage'
    return totals, archive, monthly


def _secret():
    value = os.getenv('ADMIN_ACCOUNT_ENCRYPTION_KEY') or os.getenv('INGEST_TOKEN')
    if not value:
        raise ValueError('Report signing is not configured')
    return hmac.digest(value.encode(), b'ExtSecure cloud report snapshots v1', 'sha256')


def _ticket(data):
    body = _b64(_json(data))
    return body + '.' + _b64(hmac.digest(_secret(), body.encode(), 'sha256'))


def _unticket(value, now):
    if len(value) > 2500:
        raise ValueError('Invalid report ticket')
    body, signature = value.split('.')
    if not hmac.compare_digest(_unb64(signature), hmac.digest(_secret(), body.encode(), 'sha256')):
        raise ValueError('Invalid report ticket')
    data = json.loads(_unb64(body))
    if type(data.get('expires')) is not int or data['expires'] < now.timestamp():
        raise ValueError('Expired report ticket')
    if data.get('kind') not in {'weekly', 'monthly'} or data.get('language') not in {'en', 'ar'}:
        raise ValueError('Invalid report ticket')
    return data


def _bounds(kind, period, *, manual=False):
    start = datetime.fromisoformat(period + ('-01' if kind == 'monthly' else '')).replace(tzinfo=timezone.utc)
    if kind == 'weekly':
        if start.weekday() != (0 if manual else 6):
            raise ValueError('Invalid report week boundary')
        return start, start+timedelta(days=7)
    return start, (start+timedelta(days=32)).replace(day=1)


class Poll(BaseModel):
    model_config = ConfigDict(extra='forbid')
    limit: int = Field(2, ge=1, le=MAX_BATCH)


class Complete(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ticket: str = Field(min_length=50, max_length=2500, repr=False)
    narrative: Narrative
    model: str = Field(max_length=100)
    model_digest: str = Field(max_length=64)


class Failed(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ticket: str = Field(min_length=50, max_length=2500, repr=False)
    stage: str = Field(pattern='^(cloud_ai|validation|connection|generation)$')


def queue_requested_report(db, payload, actor, *, now=None):
    from alba_security.intelligence import period_bounds, report_data
    period_bounds(payload.kind,payload.period,now=now)
    saved=_existing(db,payload.kind,payload.period,payload.language)
    if saved:
        return report_data(saved)
    reference=payload.kind+':'+payload.period+':'+payload.language
    if not db.scalar(select(GovernanceAudit.id).where(GovernanceAudit.area==AREA,
            GovernanceAudit.action=='cloud_report_requested',GovernanceAudit.reference==reference).limit(1)):
        audit(db,AREA,reference,actor,'cloud_report_requested',kind=payload.kind,
              period=payload.period,language=payload.language)
        db.commit()
    return {'status':'queued','kind':payload.kind,'period':payload.period,'language':payload.language,
            'source':'github_actions','review_required':True}


def cloud_status(db, *, now=None):
    from alba_security.report_status import report_schedule_status
    now = _utc(now or utc_now())
    result = report_schedule_status(True, now=now, path=Path('/nonexistent/extsecure-cloud-log'))
    contact = db.scalar(select(GovernanceAudit).where(GovernanceAudit.area == AREA,
        GovernanceAudit.action == 'cloud_worker_checked').order_by(GovernanceAudit.created_at.desc()).limit(1))
    last_contact = _utc(contact.created_at).isoformat() if contact else None
    for kind in ('weekly', 'monthly'):
        attempts = db.scalars(select(GovernanceAudit).where(GovernanceAudit.area==AREA,
            GovernanceAudit.action.in_(['cloud_report_started','cloud_report_saved','cloud_report_failed']),
            GovernanceAudit.details['kind'].as_string()==kind)
            .order_by(GovernanceAudit.created_at.desc(),GovernanceAudit.id.desc()).limit(1)).all()
        def expose(r):
            return {'at': _utc(r.created_at).isoformat(), 'kind': kind,
                'period': r.details.get('period'), 'status': r.details['status'],
                'stage': r.details.get('stage') if r.details['status'] == 'failed' else None}
        result[kind]['last_attempt'] = expose(attempts[0]) if attempts else None
        success = db.scalar(select(GovernanceAudit).where(GovernanceAudit.area==AREA,
            GovernanceAudit.action=='cloud_report_saved',GovernanceAudit.details['kind'].as_string()==kind)
            .order_by(GovernanceAudit.created_at.desc(),GovernanceAudit.id.desc()).limit(1))
        result[kind]['last_success'] = expose(success) if success else None
        result[kind]['next_recovery_at'] = (now.replace(minute=17, second=0, microsecond=0)
            + (timedelta(hours=1) if now.minute >= 17 else timedelta())).isoformat()
    language = os.getenv('REPORT_LANGUAGE', 'en')
    pending = sum(_existing(db,k,p,language) is None for k,p,_,_ in periods_due(now, _initialized(db,now)))
    return {'mode':'github_actions', 'enabled':True, 'runs':result, 'last_worker_contact':last_contact,
        'pending_periods':pending, 'inference':'open model on GitHub-hosted runner',
        'laptop_required':False, 'billing':'standard public-repository runners only',
        'availability_notice':'Best-effort free schedule; delayed runs are retried hourly. GitHub may disable schedules after 60 days without repository activity.',
        'worker_state':'verified' if last_contact else 'awaiting_first_run'}


def install_cloud_reports(app, session_scope):
    def authorize(request: Request):
        if not enabled():
            raise HTTPException(503, 'Cloud report automation is not enabled')
        value = request.headers.get('authorization', '')
        if not value.startswith('Bearer '):
            raise HTTPException(401, 'A trusted report workflow identity is required')
        try:
            return IDENTITY.verify(value[7:])
        except httpx.HTTPError:
            raise HTTPException(503, 'Report identity verification is temporarily unavailable') from None
        except Exception:
            raise HTTPException(401, 'Report workflow identity was not accepted') from None

    @app.post('/api/intelligence/report-automation/jobs')
    def jobs(payload: Poll, identity=Depends(authorize), db=Depends(session_scope)):
        now = utc_now()
        initialized = _initialized(db, now)
        if not db.scalar(select(GovernanceAudit.id).where(GovernanceAudit.area == AREA,
                GovernanceAudit.action == BOOTSTRAP).limit(1)):
            audit(db, AREA, 'schedule', ACTOR, BOOTSTRAP)
        audit(db, AREA, 'worker', ACTOR, 'cloud_worker_checked', source='github_actions')
        language = os.getenv('REPORT_LANGUAGE', 'en')
        if language not in {'en','ar'}:
            raise HTTPException(503, 'Choose a supported report language')
        result = []
        candidates=[]
        requested=db.scalars(select(GovernanceAudit).where(GovernanceAudit.area==AREA,
            GovernanceAudit.action=='cloud_report_requested').order_by(GovernanceAudit.created_at).limit(10000)).all()
        from alba_security.intelligence import period_bounds
        for row in requested:
            d=row.details
            try:
                if d['language'] not in {'en','ar'}:
                    continue
                start,end=period_bounds(d['kind'],d['period'],now=now)
                candidates.append((d['kind'],d['period'],start,end,d['language'],True))
            except (ValueError,KeyError):
                continue
        candidates.extend((k,p,s,e,language,False)for k,p,s,e in periods_due(now,initialized))
        seen=set()
        for kind, period, start, end, job_language, manual in candidates:
            key=(kind,period,job_language)
            if key in seen or _existing(db, kind, period, job_language):
                continue
            seen.add(key)
            totals, _, _ = _snapshot(db, kind, start, end,manual=manual)
            digest = hashlib.sha256(_json(totals)).hexdigest()
            ticket = _ticket({'kind':kind, 'period':period, 'language':job_language, 'manual':manual,'digest':digest,
                'expires':int((now+timedelta(hours=1)).timestamp())})
            codes = sorted(set(totals['finding_counts']) | set(totals['evidence_counts']))
            result.append({'kind':kind, 'period':period, 'language':job_language, 'stats':totals,
                'evidence_codes':codes, 'ticket':ticket, 'model':MODEL, 'model_digest':MODEL_DIGEST})
            audit(db, AREA, kind+':'+period, ACTOR, 'cloud_report_started', kind=kind,period=period,status='running')
            if len(result) >= payload.limit:
                break
        db.commit()
        return {'jobs':result, 'review_required':True, 'private_rows_shared':False}

    @app.post('/api/intelligence/report-automation/complete')
    def complete(payload: Complete, identity=Depends(authorize), db=Depends(session_scope)):
        now = utc_now()
        try:
            ticket = _unticket(payload.ticket, now)
            start,end = _bounds(ticket['kind'], ticket['period'],manual=ticket.get('manual',False))
            if end > now or payload.model != MODEL or payload.model_digest != MODEL_DIGEST:
                raise ValueError('Invalid report metadata')
        except Exception:
            raise HTTPException(422, 'Report metadata was not accepted') from None
        existing = _existing(db, ticket['kind'], ticket['period'], ticket['language'])
        if existing:
            return {'status':'already_saved','report_id':existing.id}
        totals, archive, monthly = _snapshot(db, ticket['kind'], start, end,manual=ticket.get('manual',False))
        if not hmac.compare_digest(hashlib.sha256(_json(totals)).hexdigest(), ticket['digest']):
            raise HTTPException(409, 'Report evidence changed; request a fresh snapshot')
        raw = payload.narrative.model_dump_json()
        fixed = SimpleNamespace(provider_name='ollama', responses=SimpleNamespace(create=lambda **_:SimpleNamespace(status='completed',output_text=raw)))
        try:
            codes = tuple(sorted(set(totals['finding_counts']) | set(totals['evidence_counts'])))
            narrative = write_narrative(totals, language=ticket['language'], purpose=ticket['kind']+' alert and explanation report',
                client=fixed, model=MODEL, evidence_codes=codes)
        except Exception:
            audit(db,AREA,ticket['kind']+':'+ticket['period'],ACTOR,'cloud_report_failed',
                kind=ticket['kind'],period=ticket['period'],status='failed',stage='validation')
            db.commit()
            raise HTTPException(422, 'The report did not pass evidence validation') from None
        narrative.update(execution='github_actions',model_digest=MODEL_DIGEST)
        body = narrative['summary']+'\n\n'+'\n'.join(narrative['recommendations'])+'\n\n'+json.dumps(totals,ensure_ascii=False,indent=2)
        subject = f"ExtSecure {ticket['kind']} security report — {ticket['period']}"
        record = IntelligenceReport(kind=ticket['kind'],period=ticket['period'],language=ticket['language'],
            stats={**totals,'archive':archive},narrative=narrative,subject=subject,body=body)
        db.add(record)
        if monthly is not None and not db.scalar(select(MonthlyReportRecord).where(MonthlyReportRecord.period == ticket['period'])):
            db.add(MonthlyReportRecord(period=ticket['period'],stats=monthly,subject=subject,
                body=body+'\n\n'+monthly['machine_learning'].get('limitation',''),summary_source='ollama'))
        audit(db,AREA,ticket['kind']+':'+ticket['period'],ACTOR,'cloud_report_saved',kind=ticket['kind'],
            period=ticket['period'],status='generated',source='github_actions',review_required=True)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = _existing(db,ticket['kind'],ticket['period'],ticket['language'])
            if not existing:
                raise
            return {'status':'already_saved','report_id':existing.id}
        return {'status':'generated','report_id':record.id,'review_required':True}

    @app.post('/api/intelligence/report-automation/failed')
    def failed(payload: Failed, identity=Depends(authorize), db=Depends(session_scope)):
        try:
            ticket = _unticket(payload.ticket, utc_now())
        except Exception:
            raise HTTPException(422, 'Report metadata was not accepted') from None
        if not _existing(db,ticket['kind'],ticket['period'],ticket['language']):
            audit(db,AREA,ticket['kind']+':'+ticket['period'],ACTOR,'cloud_report_failed',
                kind=ticket['kind'],period=ticket['period'],status='failed',stage=payload.stage)
            db.commit()
        return {'status':'recorded'}
