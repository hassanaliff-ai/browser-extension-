"""Create the current schema and upgrade the prior prototype's scan table."""

from __future__ import annotations

from sqlalchemy import Engine, inspect

from alba_security.models import Base


def ensure_schema(engine: Engine) -> None:
    """Create new tables and add the one column introduced after v0.1.

    Existing installations of the prior prototype have all other columns but
    lack ``scans.override_id``. New installations get the full schema from
    metadata. The migration keeps existing scans and alerts intact.
    """
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
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
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_scans_override_id ON scans (override_id)"
        )
