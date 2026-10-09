"""Read-only structural and attribution checks; never return account secrets."""
from sqlalchemy import inspect,text
from alba_security.database_migration import load_metadata
from alba_security.postgresql import VIEW_SQL

SCHEMA_REVISION = '2026-10-09.3'


def database_status(engine):
    if engine.dialect.name != 'postgresql':
        raise ValueError('Database health inspection requires PostgreSQL')
    metadata=load_metadata()
    inspector=inspect(engine)
    tables=set(inspector.get_table_names())
    missing_tables=sorted(set(metadata.tables)-tables)
    missing_views=sorted(set(VIEW_SQL)-set(inspector.get_view_names()))
    missing_constraints=[]
    missing_indexes=[]
    from sqlalchemy import CheckConstraint,UniqueConstraint,ForeignKeyConstraint
    for name in ('extensions','scans','domains','findings','alerts','security_events'):
        if name not in tables:continue
        known=set()
        for method in ('get_check_constraints','get_unique_constraints','get_foreign_keys'):
            known.update(item['name'] for item in getattr(inspector,method)(name))
        missing_constraints.extend(c.name for c in metadata.tables[name].constraints
            if isinstance(c,(CheckConstraint,UniqueConstraint,ForeignKeyConstraint)) and c.name and c.name not in known)
        known_indexes={item['name'] for item in inspector.get_indexes(name)}
        missing_indexes.extend(i.name for i in metadata.tables[name].indexes if i.name not in known_indexes)
    counts={};context_errors={}
    with engine.connect() as connection:
        connection.exec_driver_sql('SET TRANSACTION READ ONLY')
        # Counts are an operational snapshot, not a substitute for a backup.
        for name in sorted(set(metadata.tables)&tables):
            quoted=engine.dialect.identifier_preparer.quote(name)
            counts[name]=connection.scalar(text('SELECT count(*) FROM '+quoted))
        if not missing_tables:
            context_errors['scan_extension_device']=connection.scalar(text('''SELECT count(*) FROM scans s
                JOIN extensions e ON e.id=s.extension_id WHERE e.device_id<>s.device_id'''))
            for name in ('findings','security_events'):
                context_errors[name+'_scan_device']=connection.scalar(text(f'''SELECT count(*) FROM {name} c
                    JOIN scans s ON s.id=c.scan_id WHERE c.device_id<>s.device_id'''))
                context_errors[name+'_scan_extension']=connection.scalar(text(f'''SELECT count(*) FROM {name} c
                    JOIN scans s ON s.id=c.scan_id WHERE c.extension_id IS NOT NULL
                    AND c.extension_id IS DISTINCT FROM s.extension_id'''))
        permissions=dict(connection.execute(text('''SELECT current_user AS runtime_role,
            has_table_privilege(current_user,'governance_audit','UPDATE') AS can_update_audit,
            has_table_privilege(current_user,'governance_audit','DELETE') AS can_delete_audit,
            has_schema_privilege(current_user,current_schema(),'CREATE') AS can_create_tables''')).mappings().one()) if 'governance_audit' in tables else {}
        migrations=[row[0] for row in connection.execute(text('SELECT version FROM extsecure_schema_migrations ORDER BY version'))] if 'extsecure_schema_migrations' in tables else []
    return {'schema_revision':SCHEMA_REVISION,
        'healthy':not (missing_tables or missing_views or missing_constraints or missing_indexes or any(context_errors.values())),
        'table_count':len(tables),'view_count':len(inspector.get_view_names()),
        'table_rows':counts,'total_rows':sum(counts.values()),'context_errors':context_errors,
        'missing_tables':missing_tables,'missing_views':missing_views,
        'missing_constraints':sorted(missing_constraints),'missing_indexes':sorted(missing_indexes),
        'applied_migrations':migrations,
        'permissions':permissions}
