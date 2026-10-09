"""Bound, portable database queries. HTTP callers must enforce existing role access."""
from datetime import datetime,timezone
from urllib.parse import urlsplit
import ipaddress
import idna
from sqlalchemy import select,func,case
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from alba_security.models import Domain,Scan,Device,new_id,utc_now


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
    if not isinstance(start,datetime) or not isinstance(end,datetime) or start.tzinfo is None or end.tzinfo is None or start>=end:
        raise ValueError('Provide increasing timezone-aware start and end timestamps')
    return start.astimezone(timezone.utc),end.astimezone(timezone.utc)


def scan_history_query(start,end,*,device_id=None,limit=200):
    start,end=utc_range(start,end)
    if type(limit) is not int or not 1<=limit<=500:
        raise ValueError('History limit must be 1–500')
    stmt=select(Scan.id,Scan.device_id,Device.name.label('device_name'),Scan.extension_id,
        Domain.hostname,Scan.target_kind,Scan.score,Scan.severity,Scan.completeness,
        Scan.risk_policy_version,Scan.created_at).join(Device,Scan.device_id==Device.id).outerjoin(Domain,Scan.domain_id==Domain.id)
    stmt=stmt.where(Scan.created_at>=start,Scan.created_at<end)
    if device_id is not None:
        stmt=stmt.where(Scan.device_id==device_id)
    return stmt.order_by(Scan.created_at.desc(),Scan.id.desc()).limit(limit)


def scan_statistics_query(start,end):
    start,end=utc_range(start,end)
    return select(func.count(Scan.id).label('total_scans'),
        func.count(func.distinct(Scan.device_id)).label('unique_devices'),
        func.count(func.distinct(Scan.domain_id)).label('unique_domains'),
        func.coalesce(func.sum(case((Scan.severity.in_(['High','Critical']),1),else_=0)),0).label('high_risk_scans'),
        func.coalesce(func.sum(case((Scan.severity=='Unknown',1),else_=0)),0).label('unknown_scans')).where(Scan.created_at>=start,Scan.created_at<end)
