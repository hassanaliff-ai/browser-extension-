"""Local operator CLI: backups, migrations, monitoring and approved data exchange."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse, json, os, sys
for name in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS'):
    os.environ.setdefault(name, '1')
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from setup_postgresql import ROOT, stored_urls, admin_connection
from alba_security.dbops.common import atomic_json, private_path, utc_now
from alba_security.dbops.backup import create_backup, verify_restore
from alba_security.dbops.migrations import apply_migrations
from alba_security.dbops.monitoring import Thresholds, collect_metrics
from alba_security.dbops.transfer import export_records, import_domains, parse_time
from alba_security.dbops.benchmark import benchmark

DEFAULT_CONFIG = {'backup_every_hours': 24, 'restore_test_every_days': 7,
    'thresholds': {'database_mb': 1024, 'connections_percent': 80, 'query_seconds': 5,
        'transaction_seconds': 60, 'blocked_sessions': 0, 'growth_mb_per_day': 100}}


def paths():
    folder = ROOT / '.private/database-operations'
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def load_config():
    path = paths() / 'config.json'
    if not path.exists(): atomic_json(path, DEFAULT_CONFIG)
    value = json.loads(path.read_text(encoding='utf-8'))
    if set(value) != set(DEFAULT_CONFIG) or type(value['backup_every_hours']) is not int or type(value['restore_test_every_days']) is not int or not 1 <= value['backup_every_hours'] <= 168 or not 1 <= value['restore_test_every_days'] <= 90:
        raise ValueError('Invalid maintenance intervals')
    Thresholds(**value['thresholds'])
    return value


def monitor(admin_kwargs, database, config):
    # Read aggregate activity for this database with the already-authorized local
    # administrator. No SQL text, usernames, session IDs or other database names.
    kwargs = dict(admin_kwargs); kwargs['dbname'] = database
    url = URL.create('postgresql+psycopg', username=kwargs['user'], password=kwargs['password'],
        host=kwargs['host'], port=kwargs['port'], database=database)
    engine = create_engine(url)
    path = paths() / 'monitor.json'
    previous = json.loads(path.read_text()).get('metrics') if path.exists() else None
    try: result = collect_metrics(engine, Thresholds(**config['thresholds']), previous)
    finally: engine.dispose()
    atomic_json(path, result)
    if result['alerts']:
        with (paths() / 'alerts.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'captured_at': result['metrics']['captured_at'], 'alerts': result['alerts']}) + '\n')
    return result


def maintain(owner, app, config):
    state_path = paths() / 'maintenance.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    engine = create_engine(owner)
    now = utc_now()
    try:
        with engine.connect() as lock:
            if not lock.scalar(text('SELECT pg_try_advisory_lock(867431904)')):
                return {'status': 'already_running'}
            try:
                state['monitor'] = monitor(admin_connection(), owner.database, config)
                last = parse_time(state['last_backup_at']) if state.get('last_backup_at') else now - timedelta(days=365)
                if now - last >= timedelta(hours=config['backup_every_hours']):
                    backup = create_backup(ROOT, owner)
                    state['latest_backup'] = backup['backup_file']; state['last_backup_at'] = utc_now().isoformat()
                    atomic_json(state_path, state)  # Persist a completed backup even if restore testing fails.
                last_restore = parse_time(state['last_restore_at']) if state.get('last_restore_at') else now - timedelta(days=365)
                if now - last_restore >= timedelta(days=config['restore_test_every_days']):
                    state['restore_verification'] = verify_restore(ROOT, state['latest_backup'], admin_connection(), owner)
                    state['last_restore_at'] = utc_now().isoformat()
                state['last_run_at'] = utc_now().isoformat(); state['status'] = 'ok'; state.pop('error_type', None)
                atomic_json(state_path, state)
                return {'status': 'ok', 'monitor_status': state['monitor']['status'],
                    'latest_backup': state['latest_backup'], 'restore_verified': bool(state.get('last_restore_at'))}
            finally:
                lock.execute(text('SELECT pg_advisory_unlock(867431904)'))
    except Exception as error:
        state.update(status='failed', error_type=type(error).__name__, last_run_at=utc_now().isoformat())
        atomic_json(state_path, state)
        with (paths() / 'alerts.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'captured_at': state['last_run_at'], 'alerts': [{'code': 'maintenance_failed', 'error_type': type(error).__name__}]}) + '\n')
        raise
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('backup').add_argument('--verify-restore', action='store_true')
    sub.add_parser('restore-test').add_argument('backup_file')
    sub.add_parser('migrate')
    sub.add_parser('monitor'); sub.add_parser('maintain')
    sub.add_parser('benchmark').add_argument('--rows', type=int, default=10000)
    export = sub.add_parser('export'); export.add_argument('dataset', choices=['domains', 'scan_summaries'])
    export.add_argument('filename'); export.add_argument('--start', required=True); export.add_argument('--end', required=True)
    export.add_argument('--limit', type=int, default=500)
    imports = sub.add_parser('import-domains'); imports.add_argument('filename'); imports.add_argument('--commit', action='store_true')
    args = parser.parse_args()
    owner, app = stored_urls(); config = load_config()
    if args.command == 'backup':
        result = create_backup(ROOT, owner)
        if args.verify_restore: result['restore'] = verify_restore(ROOT, result['backup_file'], admin_connection(), owner)
    elif args.command == 'restore-test': result = verify_restore(ROOT, args.backup_file, admin_connection(), owner)
    elif args.command == 'benchmark':
        result = benchmark(admin_connection(), owner, rows=args.rows)
        atomic_json(paths() / 'benchmark.json', result)
    elif args.command == 'monitor': result = monitor(admin_connection(), owner.database, config)
    elif args.command == 'maintain': result = maintain(owner, app, config)
    else:
        engine = create_engine(owner if args.command == 'migrate' else app)
        try:
            if args.command == 'migrate': result = apply_migrations(engine, ROOT / 'sql/migrations', runtime_role=app.username)
            elif args.command == 'export': result = export_records(engine, private_path(ROOT, args.filename), args.dataset,
                parse_time(args.start), parse_time(args.end), limit=args.limit)
            else: result = import_domains(engine, private_path(ROOT, args.filename), commit=args.commit)
        finally: engine.dispose()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Database operation failed (' + type(error).__name__ + '). No private record contents or credentials are printed.', file=sys.stderr)
        sys.exit(1)
