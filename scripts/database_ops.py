"""Local operator CLI: backups, migrations and approved evidence export."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse, json, os, sys
for name in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS'):
    os.environ.setdefault(name, '1')
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from setup_postgresql import ROOT, stored_urls, admin_connection
from alba_security.dbops.common import atomic_json, private_path
from alba_security.dbops.backup import create_backup, verify_restore
from alba_security.dbops.migrations import apply_migrations
from alba_security.dbops.transfer import export_records, parse_time
from alba_security.dbops.benchmark import benchmark

def paths():
    folder = ROOT / '.private/database-operations'
    folder.mkdir(parents=True, exist_ok=True)
    return folder








def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('backup').add_argument('--verify-restore', action='store_true')
    sub.add_parser('restore-test').add_argument('backup_file')
    sub.add_parser('migrate')
    sub.add_parser('benchmark').add_argument('--rows', type=int, default=10000)
    export = sub.add_parser('export'); export.add_argument('dataset', choices=['domains', 'scan_summaries'])
    export.add_argument('filename'); export.add_argument('--start', required=True); export.add_argument('--end', required=True)
    export.add_argument('--limit', type=int, default=500)
    args = parser.parse_args()
    owner, app = stored_urls()
    if args.command == 'backup':
        result = create_backup(ROOT, owner)
        if args.verify_restore: result['restore'] = verify_restore(ROOT, result['backup_file'], admin_connection(), owner)
    elif args.command == 'restore-test': result = verify_restore(ROOT, args.backup_file, admin_connection(), owner)
    elif args.command == 'benchmark':
        result = benchmark(admin_connection(), owner, rows=args.rows)
        atomic_json(paths() / 'benchmark.json', result)
    else:
        engine = create_engine(owner if args.command == 'migrate' else app)
        try:
            if args.command == 'migrate': result = apply_migrations(engine, ROOT / 'sql/migrations', runtime_role=app.username)
            elif args.command == 'export': result = export_records(engine, private_path(ROOT, args.filename), args.dataset,
                parse_time(args.start), parse_time(args.end), limit=args.limit)
        finally: engine.dispose()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Database operation failed (' + type(error).__name__ + '). No private record contents or credentials are printed.', file=sys.stderr)
        sys.exit(1)
