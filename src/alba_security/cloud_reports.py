"""Private scheduled reports: GitHub triggers only; data stays on Render and Neon.

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

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from alba_security.governance import GovernanceAudit, audit
from alba_security.intelligence import IntelligenceReport, aggregate_period
from alba_security.llm import RECOMMENDATIONS
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
    totals, archive = aggregate_period(db,start,end)
    monthly = None
    if kind == 'monthly':
        from alba_security.monthly_ml import analyze_month
        monthly = aggregate_month(db,start.year,start.month)
        monthly['machine_learning'] = analyze_month(db,start.year,start.month)
        ml = monthly['machine_learning']
        totals['machine_learning'] = {'status':ml['status'],
            'active_training_days':int(ml.get('active_training_days',0)),
            'unusual_day_count':len(ml.get('unusual_days',[]))}
    if kind == 'weekly' and not manual:
        totals['schedule']='Sunday 09:00 Asia/Riyadh; Sunday–Saturday UTC coverage'
    return totals,archive,monthly


def statistical_narrative(stats, language):
    n=stats['total_scans'];alerts=stats['alerts_total'];explanations=stats['explanations_total']
    severity=stats['severity_counts'];coverage=stats['completeness_counts']
    high=severity.get('High',0)+severity.get('Critical',0)
    partial=coverage.get('partial',0);unknown=coverage.get('unknown',0)
    opened=stats['alerts_by_status'].get('open',0)
    if language=='ar':
        text=(f"سُجلت {n} عملية فحص خلال الفترة المحددة بالتوقيت العالمي، منها {high} عالية أو حرجة. "
              f"اكتمال الفحص: {coverage.get('complete',0)} مكتملة، و{partial} جزئية، و{unknown} غير معروفة. "
              f"سُجل {alerts} تنبيهًا، منها {opened} مفتوحة عند إعداد التقرير، و{explanations} تفسيرات محفوظة بالذكاء الاصطناعي. "
              'الأعداد تمثل أحداثًا مسجلة ولا تثبت عدد تهديدات فريدة أو أجهزة مصابة. ')
        if not n:text+='لم تُسجل عمليات فحص؛ غياب النشاط المسجل لا يثبت الأمان. '
        text+='أُعد هذا الملخص من الإحصاءات بقواعد ثابتة، دون استخدام نموذج لغوي.'
    else:
        text=(f"{n} scan events were recorded in the stated UTC period, including {high} High/Critical results. "
              f"Assessment coverage: {coverage.get('complete',0)} complete, {partial} partial and {unknown} unknown. "
              f"There were {alerts} alerts, including {opened} currently open, and {explanations} saved AI explanations. "
              'Counts describe recorded events, not unique threats or infected devices. ')
        if not n:text+='No scans were recorded; no recorded activity does not establish safety. '
        text+='This summary uses fixed rules and verified statistics; no language model was used.'
    ml=stats.get('machine_learning')
    if ml:
        if ml['status']=='ready':
            text+=(f" مراجعة النشاط: {ml['unusual_day_count']} أيام غير معتادة تستلزم المراجعة." if language=='ar'
                   else f" Activity review identified {ml['unusual_day_count']} unusual days requiring review.")
        else:text+=(' تقييم النشاط بالتعلم الآلي غير متاح بسبب عدم كفاية السجل أو تعذر النموذج.' if language=='ar'
                   else ' No ML assessment is available: history is insufficient or the model is unavailable.')
    codes=['investigate']
    if partial or unknown:codes.append('retry_unknown')
    elif high:codes.append('verify_source')
    return {'summary':text,'evidence_codes':sorted(stats['finding_counts']),
        'recommendation_codes':codes,'recommendations':[RECOMMENDATIONS[c][language=='ar']for c in codes],
        'model':None,'source':'verified_statistics','execution':'render','review_required':True}


def _candidates(db, now, initialized, language):
    from alba_security.intelligence import period_bounds
    result=[]
    requested=db.scalars(select(GovernanceAudit).where(GovernanceAudit.area==AREA,
        GovernanceAudit.action=='cloud_report_requested').order_by(GovernanceAudit.created_at).limit(10000)).all()
    for row in requested:
        d=row.details
        try:
            if d['language'] not in {'en','ar'}:continue
            start,end=period_bounds(d['kind'],d['period'],now=now)
            result.append((d['kind'],d['period'],start,end,d['language'],True))
        except (ValueError,KeyError):continue
    result.extend((k,p,s,e,language,False)for k,p,s,e in periods_due(now,initialized))
    return result


def process_due_reports(db, *, now=None):
    now=now or utc_now();initialized=_initialized(db,now)
    if not db.scalar(select(GovernanceAudit.id).where(GovernanceAudit.area==AREA,
            GovernanceAudit.action==BOOTSTRAP).limit(1)):
        audit(db,AREA,'schedule',ACTOR,BOOTSTRAP)
    audit(db,AREA,'worker',ACTOR,'cloud_worker_checked',source='github_trigger',data_shared=False)
    db.commit()
    language=os.getenv('REPORT_LANGUAGE','en')
    if language not in {'en','ar'}:raise ValueError('Unsupported report language')
    seen=set();prepared=0
    for kind,period,start,end,lang,manual in _candidates(db,now,initialized,language):
        key=(kind,period,lang)
        if key in seen or _existing(db,*key):continue
        seen.add(key)
        audit(db,AREA,kind+':'+period,ACTOR,'cloud_report_started',kind=kind,period=period,status='running')
        totals,archive,monthly=_snapshot(db,kind,start,end,manual=manual)
        narrative=statistical_narrative(totals,lang)
        subject=f'ExtSecure {kind} security report — {period}'
        body=narrative['summary']+'\n\n'+'\n'.join(narrative['recommendations'])+'\n\n'+json.dumps(totals,ensure_ascii=False,indent=2)
        db.add(IntelligenceReport(kind=kind,period=period,language=lang,stats={**totals,'archive':archive},
                                 narrative=narrative,subject=subject,body=body))
        if monthly is not None and not db.scalar(select(MonthlyReportRecord).where(MonthlyReportRecord.period==period)):
            db.add(MonthlyReportRecord(period=period,stats=monthly,subject=subject,body=body,summary_source='verified_statistics'))
        audit(db,AREA,kind+':'+period,ACTOR,'cloud_report_saved',kind=kind,period=period,
              status='generated',source='verified_statistics',data_shared=False,review_required=True)
        try:db.commit()
        except IntegrityError:
            db.rollback()
            if not _existing(db,*key):raise
        prepared+=1
        if prepared>=10:break


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
            'source':'verified_statistics','review_required':True}


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
    return {'mode':'github_trigger', 'enabled':True, 'runs':result, 'last_worker_contact':last_contact,
        'pending_periods':pending, 'inference':'disabled; deterministic statistics on Render', 'report_mode':'verified_statistics', 'llm_available':False, 'data_shared_with_github':False,
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

    @app.post('/api/intelligence/report-automation/tick',status_code=204,response_class=Response)
    def tick(identity=Depends(authorize), db=Depends(session_scope)):
        try:process_due_reports(db)
        except Exception:
            db.rollback()
            audit(db,AREA,'worker',ACTOR,'cloud_worker_failed',status='failed',stage='generation')
            db.commit()
            raise HTTPException(503,'Scheduled report preparation needs retry') from None
        # No report content, counters, dates, IDs or database records leave this route.
        return Response(status_code=204,headers={'Cache-Control':'no-store'})
