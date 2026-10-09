"""Additive database evolution and PostgreSQL reporting views."""
from sqlalchemy import inspect,select,update,CheckConstraint
from alba_security.models import Base,Scan,SecurityEvent
from alba_security.database_queries import record_domain

VIEW_SQL={
 'extsecure_risk_results':'''SELECT id AS scan_id, device_id, domain_id, target_kind, score,
 severity, completeness, risk_policy_version, override_id, created_at FROM scans''',
 'extsecure_scan_history':'''SELECT s.id AS scan_id, s.device_id, d.name AS device_name,
 s.extension_id, h.hostname, s.target_kind, s.score, s.severity, s.completeness,
 s.risk_policy_version, s.created_at FROM scans s JOIN devices d ON d.id=s.device_id
 LEFT JOIN domains h ON h.id=s.domain_id''',
 'extsecure_alert_history':'''SELECT a.id AS alert_id, a.scan_id, s.device_id, a.severity,
 a.status, a.message, a.created_at FROM alerts a JOIN scans s ON s.id=a.scan_id''',
}
for period in ('day','week','month'):
 name={'day':'daily','week':'weekly','month':'monthly'}[period]
 VIEW_SQL['extsecure_'+name+'_statistics']=f'''SELECT
 date_trunc('{period}',created_at AT TIME ZONE 'UTC') AS period_start_utc,
 count(*) AS total_scans, count(DISTINCT device_id) AS unique_devices,
 count(DISTINCT domain_id) AS unique_domains,
 count(*) FILTER (WHERE severity IN ('High','Critical')) AS high_risk_scans,
 count(*) FILTER (WHERE severity='Unknown') AS unknown_scans
 FROM scans GROUP BY 1'''


def extend_database_schema(engine):
    inspector=inspect(engine)
    columns={item['name'] for item in inspector.get_columns('scans')}
    with engine.begin() as connection:
        if 'domain_id' not in columns:
            connection.exec_driver_sql('ALTER TABLE scans ADD COLUMN domain_id VARCHAR(36) REFERENCES domains(id)')
        if 'risk_policy_version' not in columns:
            connection.exec_driver_sql('ALTER TABLE scans ADD COLUMN risk_policy_version VARCHAR(80)')
    columns={item['name'] for item in inspect(engine).get_columns('scans')}
    indexes={item['name'] for item in inspect(engine).get_indexes('scans')}
    for name,fields in [('ix_scans_domain_id',['domain_id']),('ix_scans_domain_created',['domain_id','created_at'])]:
        if name not in indexes and set(fields)<=columns:
            with engine.begin() as connection:
                connection.exec_driver_sql(f"CREATE INDEX {name} ON scans ({', '.join(fields)})")
    if engine.dialect.name!='postgresql':
        return
    with engine.begin() as connection:
        for table in ('scans','domains'):
            existing={item['name'] for item in inspect(connection).get_check_constraints(table)}
            for constraint in Base.metadata.tables[table].constraints:
                if isinstance(constraint,CheckConstraint) and constraint.name not in existing:
                    connection.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {constraint.name} CHECK ({constraint.sqltext})')
        views=set(inspect(connection).get_view_names())
        for name,sql in VIEW_SQL.items():
            if name not in views:
                connection.exec_driver_sql(f'CREATE VIEW {name} AS {sql}')


def backfill_scan_metadata(session):
    """Migrate only evidence already retained. Redacted hosts are never recovered."""
    from alba_security.governance import GovernanceState
    privacy=session.get(GovernanceState,'privacy')
    collect_hosts=bool(privacy and privacy.data.get('show_hostnames'))
    linked=0
    for scan in session.scalars(select(Scan).order_by(Scan.created_at)):
        if collect_hosts and scan.domain_id is None and scan.target_kind=='url' and not scan.target_display.startswith('URL '):
            domain=record_domain(session,scan.target_display,scan.created_at)
            if domain:
                scan.domain_id=domain;linked+=1
        if scan.risk_policy_version is None:
            events=session.scalars(select(SecurityEvent).where(SecurityEvent.scan_id==scan.id,SecurityEvent.event_type=='scan_completed'))
            scan.risk_policy_version=next((e.details.get('risk_policy_version') for e in events if e.details.get('risk_policy_version')),None)
    session.flush()
    return linked
