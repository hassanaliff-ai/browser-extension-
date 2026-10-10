import pytest
from tests.alba.test_governance import system
from alba_security.models import Base

@pytest.mark.parametrize('path',['/api/policies','/api/workflow/rules','/api/workflow/notifications','/api/controls/effectiveness','/api/controls/reviews','/api/operations/status'])
def test_removed_features_have_no_routes(system,path):
    client,app,headers,_=system
    assert path not in {r.path for r in app.routes}
    assert client.get(path,headers=headers['hasan']).status_code==404

def test_profiles_and_metadata_exclude_removed_features(system):
    client,app,headers,_=system
    profile=client.get('/api/admin/me',headers=headers['hasan']).json()
    assert not {'Security policies','Workflow automation','Control effectiveness'} & set(profile['views'])
    assert not {'security_policy_revisions','incident_workflow_rules','incident_workflow_links','incident_workflow_notices','security_control_reviews','security_navigation_evidence'} & set(Base.metadata.tables)
    assert client.get('/api/risk-policy',headers=headers['hasan']).status_code==200
