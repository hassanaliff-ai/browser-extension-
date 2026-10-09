"""Create the current schema and preserve earlier scan and authentication rows."""

from __future__ import annotations

from sqlalchemy import Engine, inspect

from alba_security.models import Base


def ensure_schema(engine: Engine) -> None:
    """Create new tables and add columns introduced after prior releases.

    Existing installations of the prior prototype have all other columns but
    lack ``scans.override_id``. New installations get the full schema from
    metadata. Session and challenge identities are added for multiple
    administrators. The migration keeps existing scans and sessions intact.
    """
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    # Sessions and challenges issued before multiple administrators belonged to
    # the original primary account. Nullable names preserve that identity.
    for table in ("admin_login_challenges", "admin_sessions"):
        if table not in inspector.get_table_names():
            continue
        columns = {item["name"] for item in inspector.get_columns(table)}
        if "username" not in columns:
            with engine.begin() as connection:
                conditional = " IF NOT EXISTS" if engine.dialect.name == "postgresql" else ""
                connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN{conditional} username VARCHAR(120)")
    if 'registered_administrators' in inspector.get_table_names():
        columns = {item['name'] for item in inspector.get_columns('registered_administrators')}
        with engine.begin() as connection:
            for name, definition in {
                'role': "VARCHAR(30) NOT NULL DEFAULT 'normal_user'",
                'approved_by': 'VARCHAR(120)',
                'approved_at': 'TIMESTAMP',
            }.items():
                if name not in columns:
                    connection.exec_driver_sql(f'ALTER TABLE registered_administrators ADD COLUMN {name} {definition}')
            if 'approved_by' not in columns:
                # Earlier releases allowed any administrator to approve. Require
                # fresh owner approval rather than inheriting an unverified grant.
                connection.exec_driver_sql("UPDATE registered_administrators SET status='pending_review' WHERE status='active'")
    if "scans" not in inspector.get_table_names():
        return
    columns = {item["name"] for item in inspector.get_columns("scans")}
    if "override_id" not in columns:
        with engine.begin() as connection:
            if engine.dialect.name == "postgresql":
                connection.exec_driver_sql(
                    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS override_id "
                    "VARCHAR(36) REFERENCES admin_overrides(id)"
                )
            elif engine.dialect.name == "sqlite":
                connection.exec_driver_sql(
                    "ALTER TABLE scans ADD COLUMN override_id "
                    "VARCHAR(36) REFERENCES admin_overrides(id)"
                )
            else:
                raise RuntimeError("Existing database upgrade supports PostgreSQL or SQLite only")
    existing_indexes={item['name'] for item in inspect(engine).get_indexes('scans')}
    if 'ix_scans_override_id' not in existing_indexes:
        with engine.begin() as connection:
            connection.exec_driver_sql('CREATE INDEX ix_scans_override_id ON scans (override_id)')
    from alba_security.postgresql import extend_database_schema
    extend_database_schema(engine)
