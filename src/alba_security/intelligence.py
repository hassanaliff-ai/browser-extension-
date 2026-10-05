"""Evidence explanations and weekly/monthly AI reports behind existing account controls."""
import base64
import hashlib
import json
from collections import Counter, defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from threading import Lock
from time import monotonic
from typing import Literal

from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column
from alba_security.models import Base, Scan, Alert, PersonalScan, new_id, utc_now
from alba_security.content_reader import ContentReadError, extract_text, read_public_page, public_url
from alba_security.llm import write_narrative, client_from_environment
from alba_security.reports import ReportConfigurationError, ReportGenerationError, _month_bounds
from alba_security.risk import risk_policy


class ExplanationRecord(Base):
    __tablename__ = 'ai_scan_explanations'
    __table_args__ = (UniqueConstraint('scan_id','language','context_digest',name='uq_ai_explanation'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id', ondelete='CASCADE'), index=True)
    language: Mapped[str] = mapped_column(String(2))
    context_digest: Mapped[str] = mapped_column(String(64))
    narrative: Mapped[dict] = mapped_column(JSON)
    context_scope: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class IntelligenceReport(Base):
    __tablename__ = 'ai_period_reports'
    __table_args__ = (UniqueConstraint('kind','period','language',name='uq_ai_period_report'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(8))
    period: Mapped[str] = mapped_column(String(10))
    language: Mapped[str] = mapped_column(String(2))
    stats: Mapped[dict] = mapped_column(JSON)
    narrative: Mapped[dict] = mapped_column(JSON)
    subject: Mapped[str] = mapped_column(String(150))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ExplanationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    language: Literal['en','ar'] = 'en'
    consent_content: bool = Field(False, strict=True)
    page_url: str | None = Field(None, max_length=2048)
    file_base64: str | None = Field(None, max_length=350000)
    content_type: Literal['text/plain','text/html','application/json','text/javascript','text/markdown','text/csv'] = 'text/plain'


class PeriodRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['weekly','monthly']
    period: str = Field(pattern=r'^20\d{2}-(?:\d{2})(?:-\d{2})?$')
    language: Literal['en','ar'] = 'en'


def period_bounds(kind, period, *, now=None):
    current = now or utc_now()
    if current.tzinfo is None:
        raise ValueError('Timezone-aware clock required')
    if kind == 'monthly':
        if len(period) != 7:
            raise ValueError('Monthly period must use YYYY-MM')
        start, end = _month_bounds(int(period[:4]),int(period[5:]))
    elif kind == 'weekly':
        day = date.fromisoformat(period)
        if not 2000 <= day.year <= 2100 or day.weekday() != 0:
            raise ValueError('Weekly period must be a Monday date (YYYY-MM-DD)')
        start = datetime.combine(day,datetime.min.time(),tzinfo=timezone.utc)
        end = start + timedelta(days=7)
    else:
        raise ValueError('Unsupported period')
    if end > current.astimezone(timezone.utc):
        raise ValueError('Choose a completed UTC period')
    return start,end


def evidence_for(scan):
    titles={item['code']:item['title'] for item in risk_policy()['signals']}
    signals=[{'code':item['code'],'status':item['status'],'title':titles[item['code']]} for item in scan.signals if item.get('code') in titles and item.get('status') in {'detected','clear','unknown'}]
    return {'severity':scan.severity,'score':scan.score,'completeness':scan.completeness,
            'target_kind':scan.target_kind if scan.target_kind in {'url','download','hash','extension','ip'} else 'unknown','signals':signals}


def explanation_data(record):
    return {'id':record.id,'scan_id':record.scan_id,'language':record.language,'created_at':record.created_at.isoformat(),
            'context_scope':record.context_scope,'review_required':True, **record.narrative}


def report_data(record):
    return {'id':record.id,'kind':record.kind,'period':record.period,'language':record.language,
            'subject':record.subject,'body':record.body,'stats':record.stats,'narrative':record.narrative,
            'created_at':record.created_at.isoformat(),'review_required':True}


def aggregate_period(db, start, end):
    scans=db.scalars(select(Scan).where(Scan.created_at>=start,Scan.created_at<end)).all()
    alerts=db.scalars(select(Alert).where(Alert.created_at>=start,Alert.created_at<end).order_by(Alert.created_at,Alert.id)).all()
    explanations=db.scalars(select(ExplanationRecord).where(ExplanationRecord.created_at>=start,ExplanationRecord.created_at<end).order_by(ExplanationRecord.created_at,ExplanationRecord.id)).all()
    # Archive every observed alert and explanation. No arbitrary "last 200" cutoff.
    # Target strings, actor names, raw page content and device IDs are excluded.
    archive={'alerts':[{'id':a.id,'scan_id':a.scan_id,'severity':a.severity,'status':a.status,'created_at':a.created_at.isoformat()} for a in alerts],
             'explanations':[explanation_data(e) for e in explanations]}
    totals={'start_utc':start.isoformat(),'end_utc':end.isoformat(),'total_scans':len(scans),
            'severity_counts':dict(Counter(s.severity if s.severity in {'Low','Medium','High','Critical','Unknown'} else 'Unknown' for s in scans)),
            'completeness_counts':dict(Counter(s.completeness if s.completeness in {'complete','partial','unknown'} else 'unknown' for s in scans)),
            'alerts_total':len(alerts),'alerts_by_status':dict(Counter(a.status if a.status in {'open','acknowledged','resolved','suppressed'} else 'unknown' for a in alerts)),
            'explanations_total':len(explanations),'explained_scans':len({e.scan_id for e in explanations}),
            'evidence_counts':dict(Counter(code for e in explanations for code in e.narrative.get('evidence_codes',[]) if code in {r['code'] for r in risk_policy()['signals']}))}
    return totals,archive


def prepare_period_report(db, payload, *, client=None, model=None, now=None):
    start,end=period_bounds(payload.kind,payload.period,now=now)
    existing=db.scalar(select(IntelligenceReport).where(IntelligenceReport.kind==payload.kind,IntelligenceReport.period==payload.period,IntelligenceReport.language==payload.language))
    if existing:
        return existing
    totals,archive=aggregate_period(db,start,end)
    narrative=write_narrative(totals,language=payload.language,purpose=payload.kind+' alert and explanation report',client=client,model=model,evidence_codes=tuple(totals['evidence_counts']))
    subject=f'ExtSecure {payload.kind} security report — {payload.period}'
    # The downloadable snapshot contains all rows; the model receives aggregate evidence only.
    body=narrative['summary']+'\n\n'+'\n'.join(narrative['recommendations'])+'\n\n'+json.dumps(totals,ensure_ascii=False,indent=2)
    record=IntelligenceReport(kind=payload.kind,period=payload.period,language=payload.language,stats={**totals,'archive':archive},narrative=narrative,subject=subject,body=body)
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        record=db.scalar(select(IntelligenceReport).where(IntelligenceReport.kind==payload.kind,IntelligenceReport.period==payload.period,IntelligenceReport.language==payload.language))
        if not record:
            raise
    return record


def install_intelligence(app, session_scope, require_actor, directory):
    from alba_security.governance import audit
    capacities=defaultdict(deque)
    capacity_lock=Lock()

    def capacity(actor):
        with capacity_lock:
            now=monotonic()
            queue=capacities[actor]
            while queue and queue[0]<=now-60:
                queue.popleft()
            if len(queue)>=3:
                raise HTTPException(429,'AI generation is limited to three requests per minute',headers={'Retry-After':'60'})
            queue.append(now)

    def owned_scan(db, actor, scan_id):
        record=db.get(Scan,scan_id)
        if directory.role(db,actor)=='normal_user':
            owner=db.get(PersonalScan,scan_id)
            if not owner or owner.username!=actor:
                record=None
        if not record:
            raise HTTPException(404,'Scan not found')
        return record

    def model_args():
        client=getattr(app.state,'intelligence_llm_client',None)
        if client:
            return client,getattr(app.state,'intelligence_model',None)
        return client_from_environment()

    @app.get('/api/intelligence/scans/{scan_id}')
    def explanations(scan_id: str, actor: str=Depends(require_actor), db: Session=Depends(session_scope)):
        owned_scan(db,actor,scan_id)
        return [explanation_data(row) for row in db.scalars(select(ExplanationRecord).where(ExplanationRecord.scan_id==scan_id).order_by(ExplanationRecord.created_at.desc()))]

    @app.post('/api/intelligence/scans/{scan_id}/explain')
    def explain(scan_id: str, payload: ExplanationRequest, actor: str=Depends(require_actor), db: Session=Depends(session_scope)):
        scan=owned_scan(db,actor,scan_id)
        if (payload.page_url or payload.file_base64) and not payload.consent_content:
            raise HTTPException(422,'Explicit consent is required before content reaches the backend and model')
        if payload.page_url and payload.file_base64:
            raise HTTPException(422,'Choose a page or a text file, not both')
        scope,context='reputation_evidence_only',{}
        try:
            # Fail before reading or transmitting content if no model is configured.
            client,model=model_args()
            capacity(actor)
            if payload.page_url:
                from alba_security.api import _target_identity
                clean,_=public_url(payload.page_url)
                if scan.target_kind!='url' or _target_identity('url',clean)[0]!=scan.target_fingerprint:
                    raise HTTPException(422,'The cleaned page URL must match this scan; scan that exact path first')
                context=read_public_page(clean)
                context.pop('url',None)
                scope='public_page_text'
            elif payload.file_base64:
                try:
                    data=base64.b64decode(payload.file_base64,validate=True)
                except ValueError:
                    raise ContentReadError('Invalid text-file encoding') from None
                if scan.target_kind!='download' or hashlib.sha256(data).hexdigest()!=scan.target_fingerprint:
                    raise HTTPException(422,'The selected file must match the scanned SHA-256')
                context=extract_text(data,payload.content_type)
                scope='selected_text_file'
            digest=hashlib.sha256(json.dumps(context,sort_keys=True).encode()).hexdigest()
            existing=db.scalar(select(ExplanationRecord).where(ExplanationRecord.scan_id==scan_id,ExplanationRecord.language==payload.language,ExplanationRecord.context_digest==digest))
            if existing:
                return explanation_data(existing)
            evidence=evidence_for(scan)
            codes=tuple(item['code'] for item in evidence['signals'])
            narrative=write_narrative({'scan':evidence,'content_context':context,'scope':scope},language=payload.language,client=client,model=model,evidence_codes=codes)
        except ContentReadError as error:
            raise HTTPException(422,str(error)) from None
        except ReportConfigurationError as error:
            raise HTTPException(503,str(error)) from None
        except ReportGenerationError as error:
            raise HTTPException(502,str(error)) from None
        record=ExplanationRecord(scan_id=scan.id,language=payload.language,context_digest=digest,narrative=narrative,context_scope=scope)
        db.add(record)
        audit(db,'intelligence',scan.id,actor,'explanation_generated',scope=scope,language=payload.language)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            record=db.scalar(select(ExplanationRecord).where(ExplanationRecord.scan_id==scan_id,ExplanationRecord.language==payload.language,ExplanationRecord.context_digest==digest))
            if not record:
                raise
        return explanation_data(record)

    @app.get('/api/intelligence/reports')
    def reports(actor: str=Depends(require_actor), db: Session=Depends(session_scope), limit: int=Query(30,ge=1,le=100)):
        return [report_data(row) for row in db.scalars(select(IntelligenceReport).order_by(IntelligenceReport.created_at.desc()).limit(limit))]

    @app.post('/api/intelligence/reports/generate')
    def generate(payload: PeriodRequest, actor: str=Depends(require_actor), db: Session=Depends(session_scope)):
        try:
            period_bounds(payload.kind,payload.period)
            capacity(actor)
            client,model=model_args()
            record=prepare_period_report(db,payload,client=client,model=model)
            audit(db,'intelligence',record.id,actor,'period_report_reviewed',kind=payload.kind,period=payload.period)
            db.commit()
            return report_data(record)
        except ReportConfigurationError as error:
            raise HTTPException(503,str(error)) from None
        except ReportGenerationError as error:
            raise HTTPException(502,str(error)) from None
        except ValueError as error:
            raise HTTPException(422,str(error)) from None
