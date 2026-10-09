from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, os, re, shutil, subprocess, uuid
import psycopg
from psycopg import sql
from sqlalchemy import MetaData, Table, inspect, select
from alba_security.database_migration import table_digest, canonical_value


def utc_now():
    return datetime.now(timezone.utc)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def private_path(root, value, *, folder='database-operations'):
    base = (Path(root) / '.private' / folder).resolve()
    path = Path(value)
    path = (path if path.is_absolute() else base / path).resolve()
    if not path.is_relative_to(base) or path == base:
        raise ValueError('Use a file inside the configured private directory')
    return path


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def pg_tool(name, url, arguments, *, timeout=600):
    binary = shutil.which(name + '.exe') or str(Path(r'C:\Program Files\PostgreSQL\18\bin') / (name + '.exe'))
    environment = dict(os.environ)
    environment['PGPASSWORD'] = url.password
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    result = subprocess.run([binary, '--host', url.host, '--port', str(url.port or 5432),
        '--username', url.username, '--dbname', url.database, '--no-password', *arguments],
        env=environment, capture_output=True, timeout=timeout, creationflags=flags)
    if result.returncode:
        # Driver/tool diagnostics may contain credentials or record contents.
        raise RuntimeError(name + ' failed; private operation was not marked successful')


@contextmanager
def disposable_database(admin_kwargs, owner_url, purpose):
    if not re.fullmatch('[a-z]+', purpose):
        raise ValueError('Invalid disposable database purpose')
    name = 'extsecure_test_' + purpose + '_' + uuid.uuid4().hex
    created = False
    try:
        with psycopg.connect(**admin_kwargs, autocommit=True) as admin:
            admin.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(name), sql.Identifier(owner_url.username)))
            created = True
        yield owner_url.set(database=name)
    finally:
        if created:
            assert re.fullmatch(r'extsecure_test_[a-z]+_[0-9a-f]{32}', name)
            with psycopg.connect(**admin_kwargs, autocommit=True) as admin:
                admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))


def snapshot_state(connection, *, include_structure=False):
    metadata = MetaData()
    metadata.reflect(bind=connection, schema='public', views=False)
    records = {}
    schema = inspect(connection)
    structure = {}
    for name in sorted(metadata.tables):
        table = metadata.tables[name]
        if not list(table.primary_key.columns):
            raise ValueError('Backup verification requires a primary key on every application table')
        count, digest = table_digest(connection, table)
        records[table.name] = {'rows': count, 'sha256': digest}
        structure[table.name] = {
            'primary_key': schema.get_pk_constraint(table.name, schema='public')['constrained_columns'],
            'columns': [(c['name'], str(c['type']), c['nullable']) for c in schema.get_columns(table.name, schema='public')],
            'constraints': sorted(str(c['name']) for method in ('get_foreign_keys', 'get_check_constraints', 'get_unique_constraints')
                for c in getattr(schema, method)(table.name, schema='public')),
            'indexes': sorted(i['name'] for i in schema.get_indexes(table.name, schema='public')),
        }
    views, view_results = {}, {}
    for name in sorted(schema.get_view_names(schema='public')):
        view = Table(name, MetaData(), schema='public', autoload_with=connection)
        views[name] = [(c['name'], str(c['type'])) for c in schema.get_columns(name, schema='public')]
        # pg_dump/restore may rewrite equivalent view expressions (e.g. array
        # casts). Verify result shape and exact sorted snapshot results instead
        # of comparing PostgreSQL's noncanonical deparsed SQL text.
        digest, count = hashlib.sha256(), 0
        for row in connection.execute(select(view).order_by(*view.columns)).mappings():
            digest.update(json.dumps(canonical_value(dict(row)),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
            digest.update(b'\n'); count += 1
        view_results[name] = {'rows': count, 'sha256': digest.hexdigest()}
    structure_hash = hashlib.sha256(json.dumps({'tables': structure, 'views': views}, sort_keys=True).encode()).hexdigest()
    result = {'tables': records, 'view_results': view_results, 'schema_sha256': structure_hash}
    if include_structure: result['_structure'] = {'tables': structure, 'views': views}
    return result
