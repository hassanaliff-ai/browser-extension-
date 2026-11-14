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

def test_manual_native_checks_query_virustotal_each_time(extension_client):
    client,monitor,application=extension_client
    install_primary_routes(application)
    lookup=AsyncMock(return_value=ScanResult('https://example.com/','url','harmless',0,0,60,5))
    application.state.vt.scan_url=lookup
    payload={'url':'https://example.com/','source':'manual','checked_at':0}
    for _ in range(2):
        response=client.post('/api/v1/check',json=payload)
        assert response.status_code==201
        assert response.json()['provider_evidence']['cached'] is False
    assert lookup.await_count==2

def test_full_page_provider_report_is_not_replaced_with_home_page_report(extension_client):
    from datetime import datetime
    target='https://www.amtso.org/check-desktop-phishing-page/'
    report_id='f19761934518c3993f38ec9968a19b8d4d48f3ae7b1d9d3c4c6eb2b6e578607f'
    stats={'malicious':12,'suspicious':0,'harmless':48,'undetected':33,'timeout':0}
    stamp=int(datetime.fromisoformat('2026-11-11T05:24:43+00:00').timestamp())
    result=_build_result(target,'url',stats,{'last_analysis_date':stamp},report_id)
    client,monitor,application=extension_client;install_primary_routes(application)
    application.state.vt.scan_url=AsyncMock(return_value=result)
    response=client.post('/api/v1/check',json={'url':target,'source':'manual','checked_at':0})
    assert response.status_code==201
    application.state.vt.scan_url.assert_awaited_once_with(target)
    evidence=response.json()['provider_evidence']
    assert evidence['engine_total']==93 and evidence['counts']['malicious']==12
    assert evidence['report_id']==report_id and evidence['analysis_at']=='2026-11-11T05:24:43+00:00'

@pytest.mark.anyio
async def test_provider_client_keeps_full_page_report_identity(respx_mock):
    import httpx
    from app.services.virustotal import VirusTotalClient
    from alba_security.reputation_evidence import scan_provider_evidence
    from tests.helpers import VT_BASE,url_id
    target='https://www.amtso.org/check-desktop-phishing-page/'
    report_id='f19761934518c3993f38ec9968a19b8d4d48f3ae7b1d9d3c4c6eb2b6e578607f'
    route=respx_mock.get(VT_BASE+'/urls/'+url_id(target)).mock(return_value=httpx.Response(200,json={'data':{'id':report_id,'attributes':{'last_analysis_stats':{'malicious':12,'suspicious':0,'harmless':48,'undetected':33,'timeout':0}}}}))
    client=VirusTotalClient('test-key')
    try:
        result=await client.scan_url(target)
        assert route.call_count==1 and result.report_id==report_id
        assert scan_provider_evidence(result)['engine_total']==93
    finally:await client.aclose()

def test_manual_file_checks_query_provider_and_never_hide_rate_limit_with_cached_result(tmp_path):
    import httpx
    from tests.alba.test_file_lookup import _app,_admin_headers,_body
    calls=[];digest='a'*64
    def provider(request):
        calls.append(request)
        if len(calls)==3:return httpx.Response(429,headers={'Retry-After':'60'})
        return httpx.Response(200,json={'data':{'id':digest,'type':'file','attributes':{'last_analysis_stats':{'malicious':0,'suspicious':0,'harmless':60,'undetected':5}}}})
    api,transport=_app(tmp_path,provider)
    with api,transport:
        headers=_admin_headers(api)
        for _ in range(2):
            result=api.post('/api/admin/downloads/scan',json=_body(digest),headers=headers).json()
            assert result['provider_evidence']['cached'] is False
        assert len(calls)==2
        result=api.post('/api/admin/downloads/scan',json=_body(digest),headers=headers).json()
        assert len(calls)==3 and result['severity']=='Unknown'
        assert result['file_lookup']['reason']=='rate_limited'
