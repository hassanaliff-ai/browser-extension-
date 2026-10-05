"""Provisioning preserves service settings and refuses credential rotation."""
from pathlib import Path

from argon2 import PasswordHasher
from dotenv import dotenv_values
import pytest

from alba_security.provision_head import provision

def test_fresh_owner_is_private_strong_and_preserves_existing_service_key(tmp_path):
    env=tmp_path/'.env'
    env.write_text('VT_API_KEY=synthetic-service-key\nADMIN_USERNAME=\n',encoding='utf-8')
    result=provision(env)
    values=dotenv_values(env)
    assert values['VT_API_KEY'] == 'synthetic-service-key'
    assert values['ADMIN_USERNAME'] == 'head-of-administrator'
    assert values['MONITORING_ENABLED'] == '1'
    assert len(values['ADMIN_TOTP_SECRET']) >= 32
    assert len(values['INGEST_TOKEN']) >= 48
    setup=Path(result['setup_file']).read_text(encoding='utf-8')
    password=next(line.removeprefix('Password: ') for line in setup.splitlines() if line.startswith('Password: '))
    assert len(password) >= 24
    assert PasswordHasher().verify(values['ADMIN_PASSWORD_HASH'],password)
    assert password not in env.read_text()
    assert (tmp_path/'.private'/'environment-before-owner.txt').read_text().startswith('VT_API_KEY=synthetic-service-key')

def test_existing_primary_account_is_never_replaced(tmp_path):
    env=tmp_path/'.env'
    original='VT_API_KEY=synthetic\nADMIN_USERNAME=existing-owner\n'
    env.write_text(original,encoding='utf-8')
    with pytest.raises(RuntimeError,match='already exist'):
        provision(env)
    assert env.read_text() == original
    assert not (tmp_path/'.private').exists()
