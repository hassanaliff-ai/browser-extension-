"""Allowlisted data exchange. Imports cannot set scores, accounts or privileges."""
from datetime import datetime, timezone
from pathlib import Path
import csv, io, json, ipaddress
from sqlalchemy import select
from sqlalchemy.orm import Session
from alba_security.database_queries import canonical_hostname, record_domain, scan_history_query, utc_range
from alba_security.models import Domain
from alba_security.governance import audit, privacy_settings
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


def validate_domain_row(row):
    if not isinstance(row, dict) or set(row) != set(DOMAIN_FIELDS):
        raise ValueError('Only hostname, first_seen and last_seen may be imported')
    host = row['hostname']
    if not isinstance(host, str) or not host or len(host) > 253 or host.strip() != host:
        raise ValueError('Invalid hostname')
    try:
        address = ipaddress.ip_address(host)
        target = 'https://[' + address.compressed + ']/' if address.version == 6 else 'https://' + address.compressed + '/'
    except ValueError:
        target = 'https://' + host + '/'
    canonical = canonical_hostname(target)
    if not canonical or any(character in host for character in '/?#@\\\r\n\t'):
        raise ValueError('Import a hostname, not a full URL or credentials')
    # Ports, URL paths and embedded credentials are not accepted as host input.
    if ':' in host and ':' not in canonical:
        raise ValueError('Invalid hostname or port')
    first, last = parse_time(row['first_seen']), parse_time(row['last_seen'])
    if first > last:
        raise ValueError('last_seen cannot precede first_seen')
    return canonical, first, last


def read_domain_import(path):
    path = Path(path)
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Import limit is 2 MiB')
    if path.suffix.lower() == '.json':
        rows = json.loads(path.read_text(encoding='utf-8-sig'))
    elif path.suffix.lower() == '.csv':
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != list(DOMAIN_FIELDS):
                raise ValueError('CSV headers must match the approved domain fields')
            rows = list(reader)
    else:
        raise ValueError('Use JSON or CSV')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 5000:
        raise ValueError('Import 1–5000 domain rows')
    return [validate_domain_row(row) for row in rows]


def import_domains(engine, path, *, commit=False):
    rows = read_domain_import(path)  # Validate the entire file before any writes.
    combined = {}
    for host, first, last in rows:
        previous = combined.get(host, (first, last))
        combined[host] = min(first, previous[0]), max(last, previous[1])
    with Session(engine) as db:
        try:
            from alba_security.governance import GovernanceState
            if db.get(GovernanceState, 'privacy') is None or not privacy_settings(db)['show_hostnames']:
                raise ValueError('Domain collection is disabled by the privacy policy')
            existing = set(db.scalars(select(Domain.hostname).where(Domain.hostname.in_(combined))))
            for host, (first, last) in combined.items():
                target = 'https://[' + host + ']/' if ':' in host else 'https://' + host + '/'
                record_domain(db, target, first)
                record_domain(db, target, last)
            result = {'input_rows': len(rows), 'distinct_domains': len(combined),
                'duplicate_rows': len(rows) - len(combined), 'new_domains': len(set(combined) - existing),
                'existing_domains': len(existing), 'committed': commit}
            audit(db, 'database', 'domain-import', 'local_database_operator', 'domain_imported',
                input_sha256=file_hash(path), **result)
            db.commit() if commit else db.rollback()
            return result
        except Exception:
            db.rollback()
            raise


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
