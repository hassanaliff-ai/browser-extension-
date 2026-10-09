"""Run the real MV3 extension in an isolated test browser; live mode records DB changes."""
from pathlib import Path
from datetime import datetime, timezone
import argparse, getpass, json, os, shutil, subprocess, sys, uuid
from setup_postgresql import ROOT, stored_urls
from sqlalchemy import create_engine
from alba_security.dbops.common import atomic_json, snapshot_state


def database_snapshot():
    owner, _ = stored_urls()
    engine = create_engine(owner)
    try:
        with engine.connect().execution_options(isolation_level='REPEATABLE READ') as db, db.begin():
            db.exec_driver_sql('SET TRANSACTION READ ONLY')
            return snapshot_state(db)
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true', help='Use TestAPI, register a QA browser, and persist benign scan evidence')
    args = parser.parse_args()
    output = ROOT / '.private/extension-smoke' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    output.mkdir(parents=True)
    before = database_snapshot() if args.live else None
    if before: atomic_json(output / 'database-before.json', before)
    environment = dict(os.environ)
    environment['EXTSECURE_TEST_OUTPUT'] = str(output)
    node = shutil.which('node')
    if not node: raise RuntimeError('Node.js is required for browser tests')
    command = [node, str(ROOT / 'extension/tests/browser-smoke.mjs')]
    if args.live: command.append('--live')
    error_log = (output / 'browser-error.log').open('w', encoding='utf-8')
    process = subprocess.Popen(command, cwd=ROOT, env=environment,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log, text=True)
    try:
        for line in process.stdout:
            data = json.loads(line)
            if data.get('credentials_required'):
                username = input('Existing head-administrator username: ').strip()
                password = getpass.getpass('Password (masked): ')
                code = getpass.getpass('Current six-digit authenticator code (masked): ')
                if len(code) != 6 or not code.isdecimal(): raise ValueError('Enter a six-digit authenticator code')
                process.stdin.write(json.dumps({'username': username, 'password': password, 'code': code}))
                process.stdin.close()
                password = code = None
            else: print(line.strip(), flush=True)
        process.wait()
        error_log.flush()
        diagnostic = (output / 'browser-error.log').read_text(encoding='utf-8')
        if diagnostic:
            # Only the smoke runner's small JSON failure summary is user-facing.
            for line in diagnostic.splitlines():
                try:
                    data = json.loads(line)
                    if 'failed_phase' in data: print(json.dumps(data), file=sys.stderr)
                except ValueError: pass
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        error_log.close()
        if before:
            after = database_snapshot(); atomic_json(output / 'database-after.json', after)
            changes = [{'table': name, 'before': old['rows'], 'after': after['tables'][name]['rows'],
                'row_content_changed': old['sha256'] != after['tables'][name]['sha256']}
                for name, old in before['tables'].items() if old != after['tables'][name]]
            atomic_json(output / 'database-changes.json', changes)
            print(json.dumps({'database_changes': changes, 'artifacts': str(output)}, indent=2))
    return process.returncode


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        print('Browser test did not complete (' + type(error).__name__ + '). No credentials are printed.', file=sys.stderr)
        sys.exit(1)
