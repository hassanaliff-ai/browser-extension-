from datetime import datetime, timedelta, timezone
from uuid import uuid4
import statistics
from sqlalchemy import create_engine, insert, text
from alba_security.models import Device, Domain, Scan, Alert
from alba_security.database_migration import load_metadata
from alba_security.schema import ensure_schema
from alba_security.database_queries import scan_history_query, report_totals_query, domain_risk_query
from alba_security.dbops.common import disposable_database, utc_now


def explain(db, statement):
    compiled = statement.compile(dialect=db.dialect, compile_kwargs={'render_postcompile': True})
    return db.exec_driver_sql('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + str(compiled), compiled.params).scalar()[0]


def benchmark(admin_kwargs, owner_url, *, rows=10000):
    if type(rows) is not int or not 1000 <= rows <= 100000:
        raise ValueError('Benchmark 1,000–100,000 synthetic scans in a disposable database')
    with disposable_database(admin_kwargs, owner_url, 'benchmark') as target:
        engine = create_engine(target)
        try:
            load_metadata(); ensure_schema(engine)
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            domains = [str(uuid4()) for _ in range(100)]
            with engine.begin() as db:
                db.execute(insert(Device), [{'id': 'benchmark-' + str(i), 'name': 'Synthetic device'} for i in range(20)])
                db.execute(insert(Domain), [{'id': identity, 'hostname': f'domain-{i}.example.test', 'first_seen': start, 'last_seen': start + timedelta(days=90)} for i, identity in enumerate(domains)])
                scans, alerts = [], []
                for i in range(rows):
                    identity = str(uuid4()); moment = start + timedelta(minutes=i)
                    scans.append({'id': identity, 'device_id': 'benchmark-' + str(i % 20), 'domain_id': domains[i % 100],
                        'target_kind': 'url', 'target_fingerprint': 'a' * 64, 'target_display': 'https://example.test/',
                        'signals': [], 'score': 80 if i % 5 == 0 else 0, 'severity': 'Critical' if i % 5 == 0 else 'Low',
                        'completeness': 'complete', 'created_at': moment})
                    if i % 5 == 0:
                        alerts.append({'id': str(uuid4()), 'scan_id': identity, 'severity': 'Critical', 'message': 'Synthetic alert', 'status': 'open', 'created_at': moment})
                    if len(scans) == 500:
                        db.execute(insert(Scan), scans); scans = []
                        if alerts: db.execute(insert(Alert), alerts); alerts = []
                if scans: db.execute(insert(Scan), scans)
                if alerts: db.execute(insert(Alert), alerts)
                db.exec_driver_sql('ANALYZE')
            end = start + timedelta(days=90)
            queries = {'device_history': scan_history_query(start, end, device_id='benchmark-0', limit=100),
                'report_totals': report_totals_query(start, end), 'domain_ranking': domain_risk_query(start, end)}
            result = {}
            with engine.connect() as db:
                for name, statement in queries.items():
                    plans = [explain(db, statement) for _ in range(5)]
                    times = sorted(plan['Execution Time'] for plan in plans)
                    result[name] = {'median_ms': round(statistics.median(times), 3), 'p95_ms': round(times[-1], 3),
                        'returned_rows': plans[-1]['Plan']['Actual Rows'], 'plan': plans[-1]['Plan']}
            # Measure a narrowly scoped alert report before/after the new index.
            with engine.begin() as db:
                db.exec_driver_sql('DROP INDEX ix_alerts_created_at')
                statement = text('SELECT count(*) FROM alerts WHERE created_at>=:start AND created_at<:end').bindparams(start=start, end=start+timedelta(hours=1))
                before = explain(db, statement)
                db.exec_driver_sql('CREATE INDEX ix_alerts_created_at ON alerts(created_at)')
                db.exec_driver_sql('ANALYZE alerts')
                after = explain(db, statement)
            return {'synthetic_scans': rows, 'captured_at': utc_now().isoformat(), 'measurements': result,
                'alert_index_comparison': {'before_ms': before['Execution Time'], 'after_ms': after['Execution Time'],
                    'before_plan': before['Plan'], 'after_plan': after['Plan']},
                'disposable_database_removed': True}
        finally:
            engine.dispose()
