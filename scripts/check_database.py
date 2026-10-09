"""Print a read-only PostgreSQL status report without credentials or record contents."""
from pathlib import Path
import json,sys
from dotenv import dotenv_values
from sqlalchemy import create_engine
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from alba_security.database_health import database_status


def main():
    engine=create_engine(dotenv_values(ROOT/'.env')['DATABASE_URL'],pool_pre_ping=True)
    try:result=database_status(engine)
    finally:engine.dispose()
    print(json.dumps(result,indent=2))
    return 0 if result['healthy'] else 1


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:
        print('Database inspection failed ('+type(error).__name__+'). Check local connection settings.',file=sys.stderr)
        sys.exit(1)
