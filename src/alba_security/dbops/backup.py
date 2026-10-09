from pathlib import Path
import json, uuid
from sqlalchemy import create_engine, text
from alba_security.dbops.common import atomic_json, disposable_database, file_hash, pg_tool, private_path, snapshot_state, utc_now


def create_backup(root, owner_url):
    folder = Path(root) / '.private/backups'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / ('extsecure-' + utc_now().strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8] + '.dump')
    engine = create_engine(owner_url)
    try:
        # pg_dump and row digests use the same exported MVCC snapshot even if
        # the API continues writing during the backup.
        with engine.connect().execution_options(isolation_level='REPEATABLE READ') as db, db.begin():
            db.exec_driver_sql('SET TRANSACTION READ ONLY')
            snapshot = db.scalar(text('SELECT pg_export_snapshot()'))
            state = snapshot_state(db)
            pg_tool('pg_dump', owner_url, ['--format=custom', '--snapshot', snapshot, '--file', str(path)])
        manifest = {'format_version': 2, 'created_at': utc_now().isoformat(), 'database': owner_url.database,
            'dump_sha256': file_hash(path), **state}
        atomic_json(path.with_suffix('.json'), manifest)
        return {'backup_file': str(path), 'tables': len(state['tables']),
            'rows': sum(t['rows'] for t in state['tables'].values()), 'sha256': manifest['dump_sha256']}
    finally:
        engine.dispose()


def verify_restore(root, backup_file, admin_kwargs, owner_url):
    path = private_path(root, backup_file, folder='backups')
    if path.suffix != '.dump' or not path.is_file():
        raise ValueError('Select a completed private PostgreSQL backup')
    manifest = json.loads(path.with_suffix('.json').read_text(encoding='utf-8'))
    if manifest.get('format_version') != 2 or file_hash(path) != manifest.get('dump_sha256'):
        raise ValueError('Backup checksum verification failed; nothing was restored')
    with disposable_database(admin_kwargs, owner_url, 'restore') as target:
        pg_tool('pg_restore', target, ['--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges', str(path)])
        engine = create_engine(target)
        try:
            with engine.connect() as db:
                db.exec_driver_sql('SET TRANSACTION READ ONLY')
                restored = snapshot_state(db)
            if restored != {'tables': manifest['tables'], 'view_results': manifest['view_results'], 'schema_sha256': manifest['schema_sha256']}:
                raise ValueError('Restored schema or row digests differ from the backup snapshot')
        finally:
            engine.dispose()
    result = {'verified': True, 'verified_at': utc_now().isoformat(), 'tables': len(manifest['tables']),
        'rows': sum(t['rows'] for t in manifest['tables'].values()), 'disposable_database_removed': True}
    atomic_json(path.with_suffix('.restore.json'), result)
    return result
