"""Freeze the local API, verify SQLite migration, and switch with automatic recovery."""
from pathlib import Path
import json,os,sqlite3,subprocess,sys,time,uuid,shutil
import httpx
from dotenv import dotenv_values,set_key
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url,URL
from setup_postgresql import ROOT,provision,admin_connection
from alba_security.database_migration import migrate_snapshot


def powershell(command):
    environment=dict(os.environ);environment.pop('PSModulePath',None)
    return subprocess.run([shutil.which('pwsh.exe') or 'powershell','-NoProfile','-Command',command],
        capture_output=True,text=True,env=environment,creationflags=subprocess.CREATE_NO_WINDOW,check=True)


def api_process():
    result=subprocess.run(['netstat.exe','-ano','-p','TCP'],capture_output=True,text=True,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
    listeners=[]
    for line in result.stdout.splitlines():
        fields=line.split()
        if len(fields)==5 and fields[0]=='TCP' and fields[1].endswith(':8765') and fields[3]=='LISTENING':
            listeners.append(int(fields[4]))
    if not listeners:return None
    if len(set(listeners))!=1:raise RuntimeError('Multiple processes listen on the API port')
    command='Get-CimInstance Win32_Process -Filter "ProcessId='+str(listeners[0])+'" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress'
    result=powershell(command)
    value=json.loads(result.stdout.strip()) if result.stdout.strip() else None
    if value and not ('uvicorn' in (value['CommandLine'] or '') and 'main:app' in (value['CommandLine'] or '')):
        raise RuntimeError('Port 8765 is used by another process; it was not stopped')
    return value


def stop_api(process):
    if process:
        powershell('Stop-Process -Id '+str(int(process['ProcessId']))+' -ErrorAction Stop')


def start_api(values):
    environment=dict(os.environ);environment.update({k:v for k,v in values.items() if v is not None})
    environment.update(PYTHONPATH=str(ROOT/'src'),OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1')
    with (ROOT/'.private/api.log').open('ab') as output:
        child=subprocess.Popen([sys.executable,'-m','uvicorn','main:app','--host','127.0.0.1','--port','8765'],cwd=ROOT,
            env=environment,stdin=subprocess.DEVNULL,stdout=output,stderr=output,creationflags=subprocess.CREATE_NO_WINDOW)
    with httpx.Client(timeout=2,trust_env=False) as client:
        for _ in range(50):
            if child.poll() is not None:break
            try:
                if client.get('http://127.0.0.1:8765/health').json().get('service')=='ExtSecure API':return
            except (httpx.HTTPError,ValueError):pass
            time.sleep(.5)
    raise RuntimeError('API failed to become ready; inspect its private log')


def activate():
    environment_path=ROOT/'.env'
    values=dotenv_values(environment_path)
    source_url=make_url(values['DATABASE_URL'])
    if source_url.get_backend_name()=='postgresql':
        print('The application already uses PostgreSQL. No records were reimported.');return
    if source_url.get_backend_name()!='sqlite' or not source_url.database or source_url.database==':memory:':
        raise ValueError('Activation expects the existing file-backed SQLite deployment')
    source_path=Path(source_url.database);source_path=(source_path if source_path.is_absolute() else ROOT/source_path).resolve()
    if not source_path.is_relative_to(ROOT) or not source_path.is_file():
        raise ValueError('The source database must be inside this project')
    _,owner_url,app_url=provision()
    destination=ROOT/'.private/updates'/('postgresql-'+uuid.uuid4().hex);destination.mkdir(parents=True)
    env_backup=environment_path.read_bytes();(destination/'previous.env').write_bytes(env_backup)
    current=api_process()
    target=None;source=None
    try:
        stop_api(current)
        with sqlite3.connect(source_path.as_uri()+'?mode=ro',uri=True) as live,sqlite3.connect(destination/'snapshot.sqlite') as backup:
            live.backup(backup)
        source=create_engine(URL.create('sqlite',database=str(destination/'snapshot.sqlite')))
        target=create_engine(owner_url,pool_pre_ping=True)
        counts=migrate_snapshot(source,target)
        (ROOT/'.private/postgresql-migration-verification.json').write_text(json.dumps({'database':'extsecure','verified_table_counts':counts,'sqlite_backup':str(destination/'snapshot.sqlite')},indent=2),encoding='utf-8')
        set_key(str(environment_path),'DATABASE_URL',app_url.render_as_string(hide_password=False))
        new_values=dotenv_values(environment_path);start_api(new_values)
        with httpx.Client(timeout=10,trust_env=False) as client:
            assert client.get('http://127.0.0.1:8765/extension/capabilities').json()['workflow_runner_started']
            assert client.get('http://127.0.0.1:8765/monitor/api/scans').status_code==401
        import psycopg
        with psycopg.connect(**admin_connection()) as admin:
            assert admin.execute("SELECT count(*) FROM pg_stat_activity WHERE datname=%s AND usename=%s AND application_name='ExtSecure API'",(app_url.database,app_url.username)).fetchone()[0]>0
        print(json.dumps({'activated':True,'database':'extsecure','verified_tables':len(counts),'existing_rows_preserved':True,'api_running':True}))
    except Exception:
        stop_api(api_process())
        environment_path.write_bytes(env_backup)
        start_api(values)
        raise RuntimeError('PostgreSQL activation failed; the SQLite configuration and API were restored') from None
    finally:
        if source:source.dispose()
        if target:target.dispose()


if __name__=='__main__':
    try:activate()
    except Exception as error:
        print('Activation did not complete ('+type(error).__name__+'). Check private recovery files; no credentials are printed.',file=sys.stderr)
        sys.exit(1)
