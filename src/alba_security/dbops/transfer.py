"""Allowlisted evidence export; account secrets and private fields are excluded."""
from datetime import datetime, timezone
from pathlib import Path
import csv, io, json
from sqlalchemy import select
from sqlalchemy.orm import Session
from alba_security.database_queries import scan_history_query, utc_range
from alba_security.models import Domain
from alba_security.governance import privacy_settings
from alba_security.dbops.common import file_hash

DOMAIN_FIELDS = ('hostname', 'first_seen', 'last_seen')
SCAN_FIELDS = ('target_kind', 'score', 'severity', 'completeness', 'risk_policy_version', 'created_at')


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError('Use ISO timestamps with a UTC offset')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Invalid ISO timestamp') from None
    if result.utcoffset() is None:
        raise ValueError('Timestamp must have a UTC offset')
    return result.astimezone(timezone.utc)








def export_records(engine, path, dataset, start, end, *, limit=500):
    start, end = utc_range(start, end)
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError('Export limit is 1–5000')
    if dataset not in {'domains', 'scan_summaries'}:
        raise ValueError('Only domains and scan_summaries are approved export datasets')
    with Session(engine) as db:
        if dataset == 'domains':
            from alba_security.governance import GovernanceState
            if db.get(GovernanceState, 'privacy') is None or not privacy_settings(db)['show_hostnames']:
                raise ValueError('Domain export is disabled by the privacy policy')
            stmt = select(Domain.hostname, Domain.first_seen, Domain.last_seen).where(
                Domain.last_seen >= start, Domain.first_seen < end).order_by(Domain.hostname).limit(limit + 1)
            fields = DOMAIN_FIELDS
        else:
            stmt = scan_history_query(start, end, limit=min(limit, 500)).limit(limit + 1)
            fields = SCAN_FIELDS
        records = db.execute(stmt).mappings().all()
        truncated = len(records) > limit
        rows = [{field: (value[field].replace(tzinfo=timezone.utc) if value[field].tzinfo is None else value[field]).isoformat() if isinstance(value[field], datetime) else value[field]
                 for field in fields} for value in records[:limit]]
    path = Path(path)
    if path.suffix == '.json':
        payload = json.dumps(rows, indent=2)
    elif path.suffix == '.csv':
        stream = io.StringIO(newline='')
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@', '\t', '\r')) else value
                             for key, value in row.items()})
        payload = stream.getvalue()
    else:
        raise ValueError('Export filename must end in .json or .csv')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='') as destination:
        destination.write(payload)
    return {'dataset': dataset, 'exported_rows': len(rows), 'truncated': truncated, 'sha256': file_hash(path)}
