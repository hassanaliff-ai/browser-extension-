"""Start the shared API on a cloud host using its private environment."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]


def configure_environment(environment):
    from sqlalchemy.engine import make_url

    required = ('DATABASE_URL', 'VT_API_KEY', 'ADMIN_USERNAME',
                'ADMIN_PASSWORD_HASH', 'ADMIN_TOTP_SECRET',
                'ADMIN_ACCOUNT_ENCRYPTION_KEY', 'INGEST_TOKEN')
    if any(not environment.get(name, '').strip() for name in required):
        raise ValueError('Complete the required private hosting environment settings')
    try:
        url = make_url(environment['DATABASE_URL'])
        if url.drivername not in {'postgres', 'postgresql', 'postgresql+psycopg'}:
            raise ValueError()
        if not url.host or url.host.lower() in {'localhost', '127.0.0.1', '::1'}:
            raise ValueError()
        if not url.database or not url.username or not url.password:
            raise ValueError()
        url = url.set(drivername='postgresql+psycopg').update_query_dict({'sslmode':'require'})
    except Exception:
        raise ValueError('Use the private hosted PostgreSQL connection string') from None
    try:
        port = int(environment.get('PORT', '10000'))
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        raise ValueError('The hosting port must be valid') from None
    environment['DATABASE_URL'] = url.render_as_string(hide_password=False)
    environment['MONITORING_ENABLED'] = '1'
    return port


def main():
    try:
        port = configure_environment(os.environ)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    import uvicorn
    uvicorn.run('prototypes.securescope.backend.primary:create_app', factory=True,
                host='0.0.0.0', port=port, workers=1, proxy_headers=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
