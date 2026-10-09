from pathlib import Path
import hashlib, re
from sqlalchemy import text

LEDGER = 'extsecure_schema_migrations'


def migration_files(folder):
    revisions = []
    for path in sorted(Path(folder).glob('*.sql')):
        match = re.fullmatch(r'([0-9]{4})_([a-z0-9_]+)\.sql', path.name)
        if not match:
            raise ValueError('Migration filenames must be NNNN_description.sql')
        body = path.read_text(encoding='utf-8')
        if '-- migrate:up\n' not in body or '-- migrate:down\n' not in body:
            raise ValueError('Each migration needs explicit up/down sections')
        up, down = body.split('-- migrate:up\n', 1)[1].split('-- migrate:down\n', 1)
        revisions.append({'version': match[1], 'description': match[2],
            'checksum': hashlib.sha256(body.encode('utf-8')).hexdigest(), 'up': up.strip(), 'down': down.strip()})
    if len({r['version'] for r in revisions}) != len(revisions) or not revisions:
        raise ValueError('Migration versions must be unique and nonempty')
    return revisions


def apply_migrations(engine, folder, *, runtime_role=None):
    revisions = migration_files(folder)
    with engine.begin() as db:
        db.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
        db.exec_driver_sql('SELECT pg_advisory_xact_lock(867431903)')
        db.exec_driver_sql('''CREATE TABLE IF NOT EXISTS extsecure_schema_migrations (
            version VARCHAR(4) PRIMARY KEY, description VARCHAR(120) NOT NULL,
            checksum VARCHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
            applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
        applied = {r['version']: dict(r) for r in db.execute(text('SELECT * FROM extsecure_schema_migrations')).mappings()}
        known = {r['version']: r for r in revisions}
        if set(applied) - set(known) or any(applied[v]['checksum'] != known[v]['checksum'] for v in applied):
            raise ValueError('Applied migration history differs from source; existing revisions must be immutable')
        if list(sorted(applied)) != [r['version'] for r in revisions[:len(applied)]]:
            raise ValueError('Applied migrations are not an ordered prefix of source history')
        changed = []
        for revision in revisions:
            if revision['version'] in applied:
                continue
            db.exec_driver_sql(revision['up'])
            db.execute(text('INSERT INTO extsecure_schema_migrations(version,description,checksum) VALUES (:version,:description,:checksum)'),
                {key: revision[key] for key in ('version', 'description', 'checksum')})
            changed.append(revision['version'])
        if runtime_role:
            quoted = engine.dialect.identifier_preparer.quote(runtime_role)
            db.exec_driver_sql('REVOKE ALL ON TABLE extsecure_schema_migrations FROM PUBLIC')
            db.exec_driver_sql('REVOKE ALL ON TABLE extsecure_schema_migrations FROM ' + quoted)
            db.exec_driver_sql('GRANT SELECT ON TABLE extsecure_schema_migrations TO ' + quoted)
    return {'applied_now': changed, 'current_version': revisions[-1]['version'], 'checksums_verified': True}


def rollback_test_migration(engine, folder):
    if not (engine.url.database or '').startswith('extsecure_test_'):
        raise ValueError('Rollback execution is limited to disposable test databases')
    revisions = {r['version']: r for r in migration_files(folder)}
    with engine.begin() as db:
        db.exec_driver_sql('SELECT pg_advisory_xact_lock(867431903)')
        current = db.execute(text('SELECT version,checksum FROM extsecure_schema_migrations ORDER BY version DESC LIMIT 1')).mappings().one()
        revision = revisions[current['version']]
        if current['checksum'] != revision['checksum']:
            raise ValueError('Migration checksum mismatch')
        db.exec_driver_sql(revision['down'])
        db.execute(text('DELETE FROM extsecure_schema_migrations WHERE version=:version'), {'version': current['version']})
    return {'rolled_back': current['version']}
