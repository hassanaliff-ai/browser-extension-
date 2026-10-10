"""Verified, transactional imports from a private SQLite snapshot into PostgreSQL."""
from datetime import datetime,timezone
import hashlib,json,importlib
from sqlalchemy import select,insert,func
from sqlalchemy.orm import Session
from alba_security.models import Base
from alba_security.schema import ensure_schema
from alba_security.postgresql import backfill_scan_metadata


def load_metadata():
    for name in ('admin_auth','file_lookup','governance','intelligence','inventory',
                 'overrides','registration','report_job','website_access','threat_blocks'):
        importlib.import_module('alba_security.'+name)
    return Base.metadata


def canonical_value(value):
    if isinstance(value,datetime):
        return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()
    if isinstance(value,dict):
        return {k:canonical_value(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):
        return [canonical_value(v) for v in value]
    return value


def table_digest(connection,table):
    digest=hashlib.sha256()
    count=0
    for row in connection.execute(select(table).order_by(*table.primary_key.columns)).mappings():
        digest.update(json.dumps(canonical_value(dict(row)),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
        digest.update(b'\n');count+=1
    return count,digest.hexdigest()


def migrate_snapshot(source_engine,target_engine):
    """Never append into a populated destination or modify the live SQLite source."""
    if source_engine.dialect.name!='sqlite' or target_engine.dialect.name!='postgresql':
        raise ValueError('Migration requires a SQLite snapshot and PostgreSQL destination')
    metadata=load_metadata()
    ensure_schema(source_engine)
    with Session(source_engine) as session:
        backfill_scan_metadata(session);session.commit()
    ensure_schema(target_engine)
    verified={}
    with source_engine.connect() as source,target_engine.begin() as target:
        for table in metadata.sorted_tables:
            if target.scalar(select(func.count()).select_from(table)):
                raise ValueError('Destination must be empty; existing PostgreSQL records were preserved')
        for table in metadata.sorted_tables:
            batch=[]
            for row in source.execute(select(table)).mappings():
                values=dict(row)
                for key,value in values.items():
                    if isinstance(value,datetime) and value.tzinfo is None:
                        values[key]=value.replace(tzinfo=timezone.utc)
                batch.append(values)
                if len(batch)==200:
                    target.execute(insert(table),batch);batch=[]
            if batch:
                target.execute(insert(table),batch)
            source_result=table_digest(source,table)
            if table_digest(target,table)!=source_result:
                raise ValueError('Migration verification failed for '+table.name)
            verified[table.name]=source_result[0]
    return verified
