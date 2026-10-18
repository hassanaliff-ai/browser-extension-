"""Run feedback and relational integration checks in a disposable PostgreSQL DB."""
from pathlib import Path
import os, subprocess, sys, uuid, argparse
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
import psycopg
from psycopg import sql
from setup_postgresql import stored_urls, admin_connection


def verify():
    parser=argparse.ArgumentParser()
    parser.add_argument('--inventory',action='store_true')
    args=parser.parse_args()
    owner,_=stored_urls()
    name='extsecure_test_containment_'+uuid.uuid4().hex
    with psycopg.connect(**admin_connection(),autocommit=True) as connection:
        connection.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(name),sql.Identifier(owner.username)))
    try:
        env=dict(os.environ)
        url=owner.set(database=name).render_as_string(hide_password=False)
        env.update(EXTSECURE_CONTAINMENT_PG_URL=url,EXTSECURE_TEST_DATABASE_URL=url,PYTHONPATH=str(ROOT/'src'))
        output=ROOT/'.private'/('feedback-pg-'+uuid.uuid4().hex)
        output.mkdir(parents=True)
        selected=['tests/alba/test_device_inventory.py'] if args.inventory else ['tests/alba/test_user_feedback.py','tests/alba/test_user_suggestions.py','tests/alba/test_postgresql_integration.py']
        result=subprocess.run([sys.executable,'-m','pytest',*selected,'-q',
            '--basetemp='+str(output/'tests')],cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        (output/'results.txt').write_text(result.stdout+result.stderr,encoding='utf-8')
        print(result.stdout,flush=True)
        if result.stderr:print(result.stderr,file=sys.stderr,flush=True)
        return result.returncode
    finally:
        # Only the exact database created by this invocation can be removed.
        assert name.startswith('extsecure_test_containment_') and len(name)==59
        with psycopg.connect(**admin_connection(),autocommit=True) as connection:
            connection.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))


if __name__=='__main__':raise SystemExit(verify())
