from dataclasses import dataclass, asdict
from datetime import datetime
import math
from sqlalchemy import text
from alba_security.dbops.common import utc_now


@dataclass(frozen=True)
class Thresholds:
    database_mb: float = 1024
    connections_percent: float = 80
    query_seconds: float = 5
    transaction_seconds: float = 60
    blocked_sessions: int = 0
    growth_mb_per_day: float = 100

    def __post_init__(self):
        values = asdict(self)
        if any(type(v) not in (float, int) or not math.isfinite(v) or v < 0 for v in values.values()):
            raise ValueError('Thresholds must be nonnegative numbers')
        if not 0 < self.connections_percent <= 100 or min(self.database_mb, self.query_seconds, self.transaction_seconds, self.growth_mb_per_day) <= 0:
            raise ValueError('Use positive limits and a connection percentage up to 100')
        if type(self.blocked_sessions) is not int:
            raise ValueError('Blocked session limit must be an integer')


def evaluate(metrics, limits, previous=None):
    alerts = []
    checks = [('database_size', metrics['database_bytes'] / 1024**2, limits.database_mb),
              ('connection_capacity', metrics['connections_percent'], limits.connections_percent),
              ('blocked_sessions', metrics['blocked_sessions'], limits.blocked_sessions),
              ('long_running_queries', metrics['long_queries'], 0),
              ('long_transactions', metrics['long_transactions'], 0)]
    growth = None
    if previous:
        elapsed = (datetime.fromisoformat(metrics['captured_at']) - datetime.fromisoformat(previous['captured_at'])).total_seconds()
        if elapsed >= 300:
            growth = (metrics['database_bytes'] - previous['database_bytes']) / 1024**2 * 86400 / elapsed
            checks.append(('database_growth', growth, limits.growth_mb_per_day))
        if metrics['deadlocks'] > previous['deadlocks']:
            alerts.append({'code': 'new_deadlocks', 'value': metrics['deadlocks'] - previous['deadlocks'], 'limit': 0})
    for code, value, limit in checks:
        if value > limit:
            alerts.append({'code': code, 'value': round(value, 3), 'limit': limit})
    return {'status': 'attention' if alerts else 'healthy', 'metrics': metrics, 'alerts': alerts,
            'growth_mb_per_day': round(growth, 3) if growth is not None else None,
            'thresholds': asdict(limits)}


def collect_metrics(engine, limits=None, previous=None):
    limits = limits or Thresholds()
    with engine.connect() as db:
        db.exec_driver_sql('SET TRANSACTION READ ONLY')
        db.exec_driver_sql("SET LOCAL statement_timeout = '10s'")
        metrics = dict(db.execute(text('''SELECT pg_database_size(current_database()) AS database_bytes,
            (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()) AS database_connections,
            (SELECT count(*)*100.0/current_setting('max_connections')::int FROM pg_stat_activity WHERE backend_type='client backend') AS connections_percent,
            (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
                AND cardinality(pg_blocking_pids(pid))>0) AS blocked_sessions,
            (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
                AND state='active' AND EXTRACT(EPOCH FROM clock_timestamp()-query_start)>:query_seconds) AS long_queries,
            (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
                AND xact_start IS NOT NULL AND EXTRACT(EPOCH FROM clock_timestamp()-xact_start)>:transaction_seconds) AS long_transactions,
            (SELECT deadlocks FROM pg_stat_database WHERE datname=current_database()) AS deadlocks'''),
            {'query_seconds': limits.query_seconds, 'transaction_seconds': limits.transaction_seconds}).mappings().one())
    metrics['connections_percent'] = float(metrics['connections_percent'])
    metrics['captured_at'] = utc_now().isoformat()
    return evaluate(metrics, limits, previous)
