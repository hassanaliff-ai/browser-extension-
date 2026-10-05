"""The prior prototype database gains exception links without losing scans."""

from sqlalchemy import create_engine, inspect

import alba_security.admin_auth  # noqa: F401
import alba_security.file_lookup  # noqa: F401
import alba_security.overrides  # noqa: F401
import alba_security.report_job  # noqa: F401
from alba_security.schema import ensure_schema


def test_existing_sqlite_scan_table_is_upgraded_in_place(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE scans (id VARCHAR(36) PRIMARY KEY, device_id VARCHAR(100))")
        connection.exec_driver_sql("INSERT INTO scans (id, device_id) VALUES ('old-scan', 'old-device')")
    ensure_schema(engine)
    assert "override_id" in {column["name"] for column in inspect(engine).get_columns("scans")}
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT id FROM scans").scalar() == "old-scan"
    # Startup is repeatable.
    ensure_schema(engine)


def test_existing_authentication_rows_gain_identity_without_losing_sessions(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'old-auth.db').as_posix()}")
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE admin_sessions (token_hash VARCHAR(64) PRIMARY KEY, expires_at DATETIME NOT NULL, revoked_at DATETIME)')
        connection.exec_driver_sql('CREATE TABLE admin_login_challenges (token_hash VARCHAR(64) PRIMARY KEY, expires_at DATETIME NOT NULL, consumed_at DATETIME)')
        connection.exec_driver_sql("INSERT INTO admin_sessions (token_hash, expires_at) VALUES ('old-token-hash', '2099-01-01')")
    ensure_schema(engine)
    for table in ['admin_sessions', 'admin_login_challenges']:
        assert 'username' in {c['name'] for c in inspect(engine).get_columns(table)}
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT token_hash FROM admin_sessions').scalar() == 'old-token-hash'
    ensure_schema(engine)
