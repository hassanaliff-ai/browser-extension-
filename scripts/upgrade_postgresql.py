"""Back up and verify an additive upgrade of an existing local PostgreSQL deployment."""
import json,os,shutil,subprocess,sys,uuid
from dotenv import dotenv_values
from sqlalchemy import create_engine
from setup_postgresql import ROOT,stored_urls,provision
from activate_postgresql import api_process,stop_api,start_api
from alba_security.database_migration import load_metadata,table_digest
from alba_security.database_health import database_status


def upgrade():
    values=dotenv_values(ROOT/'.env')
    if not values.get('DATABASE_URL','').startswith('postgresql'):
        raise ValueError('Use activation for a SQLite deployment; this tool upgrades PostgreSQL only')
    owner_url,app_url=stored_urls()
    engine=create_engine(owner_url,pool_pre_ping=True)
    destination=ROOT/'.private/updates'/('postgresql-upgrade-'+uuid.uuid4().hex)
    destination.mkdir(parents=True)
    stopped=False
    try:
        current=api_process();stop_api(current);stopped=True
        binary=shutil.which('pg_dump.exe') or r'C:\Program Files\PostgreSQL\18\bin\pg_dump.exe'
        environment=dict(os.environ);environment['PGPASSWORD']=owner_url.password
        subprocess.run([binary,'--host',owner_url.host,'--port',str(owner_url.port),
            '--username',owner_url.username,'--dbname',owner_url.database,'--format=custom',
            '--file',str(destination/'before-upgrade.dump'),'--no-password'],
            env=environment,capture_output=True,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
        metadata=load_metadata()
        with engine.connect() as connection:
            before={table.name:table_digest(connection,table) for table in metadata.sorted_tables}
        provision()
        with engine.connect() as connection:
            after={table.name:table_digest(connection,table) for table in metadata.sorted_tables}
        if before!=after:raise RuntimeError('Existing row verification did not match')
        runtime=create_engine(app_url,pool_pre_ping=True)
        try:status=database_status(runtime)
        finally:runtime.dispose()
        if not status['healthy']:raise RuntimeError('Schema inspection did not pass')
        (destination/'verification.json').write_text(json.dumps({'existing_rows_preserved':True,
            'verified_tables':len(before),'database_status':status},indent=2),encoding='utf-8')
        print(json.dumps({'upgraded':True,'schema_revision':status['schema_revision'],
            'verified_tables':len(before),'preserved_rows':status['total_rows'],
            'reporting_views':status['view_count'],'backup_created':True}))
    finally:
        engine.dispose()
        if stopped:start_api(values)


if __name__=='__main__':
    try:upgrade()
    except Exception as error:
        print('Database upgrade did not complete ('+type(error).__name__+'). Keep private backups and inspect the local deployment.',file=sys.stderr)
        sys.exit(1)
