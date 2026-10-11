"""Idempotent report generation for the native weekly/monthly schedule."""
from datetime import datetime,timedelta,timezone
from sqlalchemy import select
from alba_security.models import utc_now
from alba_security.intelligence import IntelligenceReport,PeriodRequest,prepare_period_report
from alba_security.governance import audit

def scheduled_period(kind,now=None):
    current=now or utc_now()
    if current.tzinfo is None:
        raise ValueError('Timezone-aware clock required')
    current=current.astimezone(timezone.utc)
    if kind=='weekly':
        sunday=current.date()-timedelta(days=(current.weekday()+1)%7)
        end=datetime.combine(sunday,datetime.min.time(),tzinfo=timezone.utc)
        start=end-timedelta(days=7)
        return PeriodRequest(kind='weekly',period=start.date().isoformat()),(start,end)
    if kind=='monthly':
        previous=current.date().replace(day=1)-timedelta(days=1)
        return PeriodRequest(kind='monthly',period=previous.strftime('%Y-%m')),None
    raise ValueError('Unsupported report frequency')

def generate_scheduled_report(db,kind,*,language='en',now=None,client=None,model=None):
    payload,bounds=scheduled_period(kind,now)
    payload=payload.model_copy(update={'language':language})
    if language not in {'en','ar'}:
        raise ValueError('Unsupported report language')
    existing=db.scalar(select(IntelligenceReport).where(IntelligenceReport.kind==kind,
        IntelligenceReport.period==payload.period,IntelligenceReport.language==language))
    record=prepare_period_report(db,payload,client=client,model=model,now=now,scheduled_bounds=bounds)
    if existing is None:
        audit(db,'intelligence',record.id,'system','scheduled_report_generated',kind=kind,
              period=record.period,time_zone='Asia/Riyadh',time='09:00',review_required=True)
        db.commit()
    return record,existing is None
