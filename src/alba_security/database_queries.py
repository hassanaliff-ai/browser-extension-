"""Bound, portable database queries. HTTP callers must enforce existing role access."""
from dataclasses import dataclass
from datetime import datetime,timezone
from urllib.parse import urlsplit
import ipaddress
import idna
from sqlalchemy import select,func,case,or_,and_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from alba_security.models import Domain,Scan,Device,Finding,Alert,SecurityEvent,new_id,utc_now


@dataclass(frozen=True)
class ScanCursor:
    """Position in descending scan history, scoped by the caller's filters."""
    created_at: datetime
    scan_id: str

    def __post_init__(self):
        if not isinstance(self.created_at, datetime) or self.created_at.utcoffset() is None:
            raise ValueError('A cursor timestamp must have a UTC offset')
        if not isinstance(self.scan_id, str) or not 1 <= len(self.scan_id) <= 36:
            raise ValueError('A cursor scan ID must contain 1–36 characters')


def canonical_hostname(target: str) -> str | None:
    try:
        url=urlsplit(target)
        if url.scheme not in {'http','https'} or url.username or url.password or not url.hostname:
            return None
        host=url.hostname.rstrip('.')
        try:
            return ipaddress.ip_address(host).compressed
        except ValueError:
            return idna.encode(host,uts46=True,std3_rules=True).decode('ascii').lower()
    except (ValueError,idna.IDNAError):
        return None


def record_domain(db,target,now=None):
    """An atomic upsert avoids duplicate hosts when two scans arrive together."""
    hostname=canonical_hostname(target)
    if not hostname:
        return None
    now=now or utc_now()
    dialect=db.get_bind().dialect.name
    if dialect not in {'postgresql','sqlite'}:
        raise RuntimeError('Domain persistence supports PostgreSQL and SQLite')
    stmt=(pg_insert if dialect=='postgresql' else sqlite_insert)(Domain).values(
        id=new_id(),hostname=hostname,first_seen=now,last_seen=now)
    stmt=stmt.on_conflict_do_update(index_elements=[Domain.hostname],set_={
        'last_seen':case((Domain.last_seen<now,now),else_=Domain.last_seen),
        'first_seen':case((Domain.first_seen>now,now),else_=Domain.first_seen)}).returning(Domain.id)
    return db.scalar(stmt)


def utc_range(start,end):
    if not isinstance(start,datetime) or not isinstance(end,datetime) or start.utcoffset() is None or end.utcoffset() is None or start>=end:
        raise ValueError('Provide increasing timezone-aware start and end timestamps')
    return start.astimezone(timezone.utc),end.astimezone(timezone.utc)


def scan_history_query(start,end,*,device_id=None,limit=200,before=None):
    start,end=utc_range(start,end)
    if type(limit) is not int or not 1<=limit<=500:
        raise ValueError('History limit must be 1–500')
    stmt=select(Scan.id,Scan.device_id,Device.name.label('device_name'),Scan.extension_id,
        Domain.hostname,Scan.target_kind,Scan.score,Scan.severity,Scan.completeness,
        Scan.risk_policy_version,Scan.created_at).join(Device,Scan.device_id==Device.id).outerjoin(Domain,Scan.domain_id==Domain.id)
    stmt=stmt.where(Scan.created_at>=start,Scan.created_at<end)
    if device_id is not None:
        stmt=stmt.where(Scan.device_id==device_id)
    if before is not None:
        if not isinstance(before, ScanCursor):
            raise ValueError('Use a ScanCursor for the history position')
        position=before.created_at.astimezone(timezone.utc)
        stmt=stmt.where(or_(Scan.created_at < position,
                           and_(Scan.created_at == position, Scan.id < before.scan_id)))
    return stmt.order_by(Scan.created_at.desc(),Scan.id.desc()).limit(limit)


def scan_history_page(db,start,end,*,device_id=None,limit=100,before=None):
    """Bounded keyset pagination; caller must authorize the device/window first."""
    stmt=scan_history_query(start,end,device_id=device_id,limit=limit,before=before)
    rows=db.execute(stmt.limit(limit+1)).mappings().all()
    has_more=len(rows)>limit
    items=[dict(row) for row in rows[:limit]]
    cursor=None
    if has_more:
        last=items[-1]
        moment=last['created_at']
        # SQLite stores naive UTC timestamps; PostgreSQL returns aware values.
        if moment.tzinfo is None:moment=moment.replace(tzinfo=timezone.utc)
        cursor=ScanCursor(moment,last['id'])
    return {'items':items,'next_cursor':cursor}


def domain_risk_query(start,end,*,device_id=None,limit=100):
    """Prioritize observed domains without persisting full browsing URLs."""
    start,end=utc_range(start,end)
    if type(limit) is not int or not 1<=limit<=500:
        raise ValueError('Domain limit must be 1–500')
    stmt=select(Domain.id,Domain.hostname,func.count(Scan.id).label('total_scans'),
        func.max(Scan.score).label('highest_score'),func.max(Scan.created_at).label('last_scan'),
        func.sum(case((Scan.severity.in_(['High','Critical']),1),else_=0)).label('high_risk_scans'),
        func.sum(case((Scan.severity=='Unknown',1),else_=0)).label('unknown_scans')).join(Scan,Scan.domain_id==Domain.id)
    stmt=stmt.where(Scan.created_at>=start,Scan.created_at<end)
    if device_id is not None:stmt=stmt.where(Scan.device_id==device_id)
    return stmt.group_by(Domain.id,Domain.hostname).order_by(
        func.max(Scan.score).desc().nulls_last(),func.max(Scan.created_at).desc(),Domain.id).limit(limit)


def report_totals_query(start,end,*,device_id=None):
    """Independent scalar aggregates avoid multiplying scans by child rows."""
    start,end=utc_range(start,end)
    scan_filters=[Scan.created_at>=start,Scan.created_at<end]
    if device_id is not None:scan_filters.append(Scan.device_id==device_id)
    scan_count=select(func.count()).select_from(Scan).where(*scan_filters)
    fields=[scan_count.scalar_subquery().label('total_scans')]
    for name,model in [('findings',Finding),('alerts',Alert),('events',SecurityEvent)]:
        stmt=select(func.count()).select_from(model).where(model.created_at>=start,model.created_at<end)
        if device_id is not None:
            stmt=stmt.join(Scan,model.scan_id==Scan.id).where(Scan.device_id==device_id)
        fields.append(stmt.scalar_subquery().label(name))
    fields.append(scan_count.where(Scan.severity.in_(['High','Critical'])).scalar_subquery().label('high_risk_scans'))
    fields.append(scan_count.where(Scan.severity=='Unknown').scalar_subquery().label('unknown_scans'))
    return select(*fields)


def scan_statistics_query(start,end):
    start,end=utc_range(start,end)
    return select(func.count(Scan.id).label('total_scans'),
        func.count(func.distinct(Scan.device_id)).label('unique_devices'),
        func.count(func.distinct(Scan.domain_id)).label('unique_domains'),
        func.coalesce(func.sum(case((Scan.severity.in_(['High','Critical']),1),else_=0)),0).label('high_risk_scans'),
        func.coalesce(func.sum(case((Scan.severity=='Unknown',1),else_=0)),0).label('unknown_scans')).where(Scan.created_at>=start,Scan.created_at<end)
