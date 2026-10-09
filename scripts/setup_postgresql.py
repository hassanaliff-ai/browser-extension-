"""Provision a dedicated local PostgreSQL database; keep secrets out of source control."""
from pathlib import Path
import argparse,json,os,secrets,subprocess,sys,shutil
from dotenv import dotenv_values
from sqlalchemy import create_engine,inspect
from sqlalchemy.engine import URL
import psycopg
from psycopg import sql

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from alba_security.database_migration import load_metadata,migrate_snapshot
from alba_security.schema import ensure_schema
from alba_security.postgresql import VIEW_SQL


def secure_transform(value,decrypt=False):
    if os.name!='nt':
        raise RuntimeError('The local masked credential file requires Windows')
    body="""[Console]::InputEncoding=[Text.UTF8Encoding]::new(); [Console]::OutputEncoding=[Text.UTF8Encoding]::new();
    $taskValue=[Console]::In.ReadToEnd(); """
    if decrypt:
        body+="""$taskSecure=ConvertTo-SecureString $taskValue;
        $taskPointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecure);
        try {[Console]::Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskPointer))}
        finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer)}"""
    else:
        body+="""$taskSecure=ConvertTo-SecureString $taskValue -AsPlainText -Force;
        [Console]::Write((ConvertFrom-SecureString $taskSecure))"""
    environment=dict(os.environ);environment.pop('PSModulePath',None)
    result=subprocess.run([shutil.which('pwsh.exe') or 'powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command',body],input=value,
        text=True,encoding='utf-8',capture_output=True,env=environment,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError('Windows credential encryption failed')
    return result.stdout.strip()


def admin_connection(root=None):
    root=root or ROOT
    credential=json.loads((root/'.private/postgresql-admin-connection.json').read_text(encoding='utf-8-sig'))
    if credential['host'] not in {'127.0.0.1','localhost','::1'}:
        raise ValueError('This setup tool is limited to the local PostgreSQL server')
    return dict(host=credential['host'],port=int(credential['port']),user=credential['username'],
        password=secure_transform(credential['password_dpapi'],decrypt=True),dbname='postgres',connect_timeout=8)


def stored_urls(root=None):
    root=root or ROOT
    data=json.loads((root/'.private/postgresql-deployment.json').read_text(encoding='utf-8'))
    def url(role):
        return URL.create('postgresql+psycopg',username=data[role+'_role'],
            password=secure_transform(data[role+'_password_dpapi'],decrypt=True),
            host=data['host'],port=data['port'],database=data['database'])
    return url('owner'),url('app')


def provision():
    private=ROOT/'.private';private.mkdir(exist_ok=True)
    path=private/'postgresql-deployment.json'
    connection=admin_connection()
    old=json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
    configuration=old or dict(database='extsecure',host=connection['host'],port=connection['port'],
        owner_role='extsecure_owner',app_role='extsecure_app')
    with psycopg.connect(**connection,autocommit=True) as admin:
        if not old:
            existing=admin.execute('SELECT rolname FROM pg_roles WHERE rolname IN (%s,%s)',
                (configuration['owner_role'],configuration['app_role'])).fetchall()
            database_exists=admin.execute('SELECT 1 FROM pg_database WHERE datname=%s',(configuration['database'],)).fetchone()
            if existing or database_exists:
                raise ValueError('Project names already exist without matching private configuration; no existing roles or database were changed')
        for kind in ('owner','app'):
            name=configuration[kind+'_role']
            exists=admin.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(name,)).fetchone()
            if exists and not old:
                raise ValueError('A project role already exists without matching local configuration; existing roles were preserved')
            if not exists:
                password=secrets.token_urlsafe(40)
                configuration[kind+'_password_dpapi']=secure_transform(password)
                path.write_text(json.dumps(configuration,indent=2),encoding='utf-8')
                admin.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}').format(sql.Identifier(name),sql.Literal(password)))
        owner=admin.execute('SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=%s',(configuration['database'],)).fetchone()
        if owner and owner[0]!=configuration['owner_role']:
            raise ValueError('The database name belongs to another owner; no existing database was changed')
        if not owner:
            admin.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(configuration['database']),sql.Identifier(configuration['owner_role'])))
        admin.execute(sql.SQL('ALTER DATABASE {} SET timezone TO {}').format(sql.Identifier(configuration['database']),sql.Literal('UTC')))
    path.write_text(json.dumps(configuration,indent=2),encoding='utf-8')
    owner_url,app_url=stored_urls()
    engine=create_engine(owner_url,pool_pre_ping=True)
    metadata=load_metadata();ensure_schema(engine)
    with engine.begin() as db:
        db.exec_driver_sql('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
        db.exec_driver_sql('REVOKE ALL ON DATABASE extsecure FROM PUBLIC')
        db.exec_driver_sql('GRANT CONNECT ON DATABASE extsecure TO extsecure_app')
        db.exec_driver_sql('GRANT USAGE ON SCHEMA public TO extsecure_app')
        # Audit records are append-only for the API runtime, while the owner
        # retains explicit migration/maintenance access.
        audit_tables={'governance_audit','admin_override_audit'}
        for name in metadata.tables:
            quoted=engine.dialect.identifier_preparer.quote(name)
            db.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {quoted} TO extsecure_app')
            if name in audit_tables:
                db.exec_driver_sql(f'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE {quoted} FROM extsecure_app')
        for name in VIEW_SQL:
            db.exec_driver_sql(f'GRANT SELECT ON TABLE {name} TO extsecure_app')
        db.exec_driver_sql('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO extsecure_app')
    engine.dispose()
    return configuration,owner_url,app_url


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sqlite-snapshot',type=Path,help='Import a private snapshot into an empty destination; live source is never modified')
    args=parser.parse_args()
    configuration,owner_url,_=provision()
    counts=None
    if args.sqlite_snapshot:
        snapshot=args.sqlite_snapshot.resolve()
        if not snapshot.is_file() or not snapshot.is_relative_to((ROOT/'.private').resolve()):
            raise ValueError('Use a snapshot inside this project\'s private directory')
        source=create_engine(URL.create('sqlite',database=str(snapshot)))
        target=create_engine(owner_url,pool_pre_ping=True)
        try:counts=migrate_snapshot(source,target)
        finally:source.dispose();target.dispose()
    print(json.dumps({'database':configuration['database'],'tables':len(load_metadata().tables),
        'reporting_views':len(VIEW_SQL),'runtime_is_superuser':False,'verified_rows':counts}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        # SQLAlchemy exception strings may include bound values or URLs.
        print('PostgreSQL setup did not complete ('+type(error).__name__+'). Existing application configuration was not switched.',file=sys.stderr)
        sys.exit(1)
