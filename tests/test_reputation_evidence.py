from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from sqlalchemy import select
from app.services.virustotal import ScanResult, _build_result, UpstreamError
from alba_security.reputation_evidence import provider_evidence, incident_rule
from alba_security.governance import IncidentCase
from tests.test_extension import extension_client
from prototypes.securescope.backend.primary import install_primary_routes

@pytest.mark.parametrize('stats', [{'malicious':True},{'malicious':-1},{'malicious':'3'}])
def test_provider_counts_reject_invalid_values(stats):
    with pytest.raises(ValueError):provider_evidence(stats)
    with pytest.raises(UpstreamError):_build_result('https://example.com','url',stats)

def test_provider_categories_are_bounded_to_detected_engine_labels():
    result=_build_result('https://example.com','url',{'malicious':1}, {'last_analysis_date':1700000000,'last_analysis_results':{
        'a':{'category':'malicious','result':'Phishing'},'b':{'category':'harmless','result':'ransomware'},'c':'bad'}})
    assert result.categories==('phishing',)
    assert result.engine_stats=={'malicious':1}
    evidence=provider_evidence(result.engine_stats,categories=result.categories)
    assert evidence['counts']['harmless'] is None
    assert evidence['categories']==['phishing']

@pytest.mark.parametrize('kind,signals,expected',[
 ('url',['malicious_url'],'malicious_website'),('download',['malicious_file_hash'],'malicious_download'),
 ('ip',['malicious_ip'],'malicious_ip'),('url',['suspicious_url'],'suspicious_reputation'),
 ('extension',['sensitive_permission'],'extension_risk'),('url',['new_domain'],'domain_age'),('url',[],'manual_review')])
def test_incident_categories_follow_actual_scan_evidence(kind,signals,expected):
    scan=SimpleNamespace(target_kind=kind,override_id=None,signals=[{'code':s,'status':'detected'} for s in signals])
    rule=incident_rule(scan)
    assert rule['category']==expected
    if expected in {'domain_age','manual_review','extension_risk'}:assert not rule['auto_eligible']

@pytest.mark.parametrize('malicious,suspicious,severity,category',[
 (1,0,'Critical','malicious_website'),(0,1,'Medium','suspicious_reputation'),(0,0,'Low','manual_review')])
def test_real_scan_persists_counts_and_creates_evidence_based_case(extension_client,malicious,suspicious,severity,category):
    client,monitor,application=extension_client
    install_primary_routes(application)
    application.state.vt.scan_url=AsyncMock(return_value=ScanResult('https://example.com/','url','harmless',malicious,suspicious,60,5))
    result=client.post('/api/v1/check',json={'url':'https://example.com/','source':'manual','checked_at':0}).json()
    assert result['severity']==severity
    assert result['provider_evidence']['counts']=={'malicious':malicious,'suspicious':suspicious,'harmless':60,'undetected':5}
    history=client.get('/monitor/api/my/scans/'+result['id']).json()
    assert history['provider_evidence']==result['provider_evidence']
    with monitor.state.session_factory() as db:
        cases=list(db.scalars(select(IncidentCase).where(IncidentCase.scan_id==result['id'])))
        assert len(cases)==(1 if malicious or suspicious else 0)
    if malicious or suspicious:
        case=client.get('/monitor/api/cases/'+cases[0].id).json()
        assert case['category']==category
        assert case['provider_evidence']==history['provider_evidence']
        again=client.post('/monitor/api/cases',json={'scan_id':result['id'],'title':'Repeated review request','assignee':'extension-test-owner'}).json()
        assert again['id']==cases[0].id
    if malicious:assert result['containment']['active']

def test_phishing_requires_explicit_provider_label(extension_client):
    client,monitor,application=extension_client
    install_primary_routes(application)
    application.state.vt.scan_url=AsyncMock(return_value=ScanResult('https://example.com/','url','malicious',3,0,60,5,categories=('phishing',)))
    result=client.post('/api/v1/check',json={'url':'https://example.com/','source':'manual','checked_at':0}).json()
    case=client.get('/monitor/api/cases/'+result['case_id']).json()
    assert case['category']=='phishing' and 'Phishing' in case['title']

def test_unknown_provider_does_not_create_a_case(extension_client):
    from app.services.virustotal import RateLimitError
    client,monitor,application=extension_client
    install_primary_routes(application)
    application.state.vt.scan_url=AsyncMock(side_effect=RateLimitError())
    result=client.post('/api/v1/check',json={'url':'https://example.com/','source':'manual','checked_at':0}).json()
    assert result['severity']=='Unknown' and result['score'] is None
    assert result['case_id'] is None and result['provider_evidence']['status']=='unavailable'
    assert result['lookup_status']=='unavailable'

def test_known_rdap_cannot_hide_unavailable_virustotal(extension_client,monkeypatch):
    from app.services.virustotal import RateLimitError
    client,monitor,application=extension_client
    install_primary_routes(application)
    monkeypatch.setattr(application.state.domain_age,'lookup',lambda _: {'status':'Known','age_days':90})
    application.state.vt.scan_url=AsyncMock(side_effect=RateLimitError())
    result=client.post('/api/v1/check',json={'url':'https://example.com/','source':'manual','checked_at':0}).json()
    assert result['severity']=='Unknown' and result['score'] is None and result['case_id'] is None
    assert result['domain_age']['status']=='Known'

def test_additive_cache_migration_preserves_legacy_rows():
    from sqlalchemy import create_engine,inspect,text
    from alba_security.schema import ensure_schema
    engine=create_engine('sqlite://')
    with engine.begin() as db:
        db.exec_driver_sql('CREATE TABLE file_reputation_cache (sha256 VARCHAR(64) PRIMARY KEY, verdict VARCHAR(16), malicious_count INTEGER, suspicious_count INTEGER, checked_at TIMESTAMP, expires_at TIMESTAMP)')
        db.exec_driver_sql("INSERT INTO file_reputation_cache VALUES ('legacy-hash','malicious',4,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
    ensure_schema(engine)
    assert 'provider_evidence' in {c['name'] for c in inspect(engine).get_columns('file_reputation_cache')}
    with engine.connect() as db:
        assert db.execute(text('SELECT verdict, malicious_count, provider_evidence FROM file_reputation_cache')).one()==('malicious',4,None)
    engine.dispose()
