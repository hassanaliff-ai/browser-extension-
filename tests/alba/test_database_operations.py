from datetime import datetime, timedelta, timezone
import json
import pytest
from sqlalchemy.orm import Session
from alba_security.models import Domain
from alba_security.governance import GovernanceState, initialize_governance
from alba_security.database_queries import record_domain
from alba_security.dbops.transfer import export_records
from alba_security.dbops.common import private_path
from alba_security.dbops.migrations import migration_files
from tests.alba.test_database_queries import engine

NOW = datetime(2026,10,9,tzinfo=timezone.utc)

def test_safe_export_limits_and_no_overwrite(engine,tmp_path):
    with Session(engine) as db:
        initialize_governance(db)
        record_domain(db,'https://example.com/',NOW)
        record_domain(db,'https://second.example/',NOW)
        db.commit()
    out=tmp_path/'domains.json'
    result=export_records(engine,out,'domains',NOW,NOW+timedelta(days=2),limit=1)
    assert result['exported_rows']==1 and result['truncated']
    assert set(json.loads(out.read_text())[0])=={'hostname','first_seen','last_seen'}
    with pytest.raises(FileExistsError):export_records(engine,out,'domains',NOW,NOW+timedelta(days=2))
    with pytest.raises(ValueError):export_records(engine,tmp_path/'secret.json','admin_sessions',NOW,NOW+timedelta(days=2))

def test_domain_export_respects_privacy(engine,tmp_path):
    with Session(engine) as db:
        initialize_governance(db)
        state=db.get(GovernanceState,'privacy');state.data={**state.data,'show_hostnames':False};db.commit()
    with pytest.raises(ValueError):export_records(engine,tmp_path/'out.json','domains',NOW,NOW+timedelta(days=2))

@pytest.mark.parametrize('value',['../secret.json','../../.env','nested/../../../secret.json'])
def test_private_exchange_paths_cannot_escape(tmp_path,value):
    with pytest.raises(ValueError):private_path(tmp_path,value)

def test_migrations_require_unique_versions_and_up_down_sections(tmp_path):
    (tmp_path/'0001_first.sql').write_text('-- migrate:up\nSELECT 1;\n-- migrate:down\nSELECT 1;\n')
    assert migration_files(tmp_path)[0]['version']=='0001'
    (tmp_path/'0001_second.sql').write_text('-- migrate:up\nSELECT 1;\n-- migrate:down\nSELECT 1;\n')
    with pytest.raises(ValueError):migration_files(tmp_path)
