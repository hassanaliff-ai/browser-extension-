import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy import select
from alba_security.content_reader import ContentReadError, extract_text, public_url, resolve_public
from alba_security.intelligence import ExplanationRecord, IntelligenceReport, PeriodRequest, aggregate_period, period_bounds, prepare_period_report
from alba_security.intelligence_runner import completed_periods
from alba_security.llm import write_narrative
from alba_security.reports import ReportGenerationError
from alba_security.models import Alert, Scan, utc_now
from tests.alba.test_governance import system, scan  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401


def model_fixture(summary=None,codes=None):
    client=Mock()
    client.responses.create.return_value=SimpleNamespace(status='completed',output_text=json.dumps({
        'summary':summary or 'Recorded reputation evidence requires careful review. The model does not establish an infection or prove safety. Review incomplete checks alongside the original evidence.',
        'evidence_codes':codes or [],'recommendation_codes':['investigate','retry_unknown']}))
    return client


@pytest.mark.parametrize('url',['http://example.com/','https://localhost/','https://host.local/','https://user:password@example.com/','https://example.com:8443/','file:///tmp/a','https://example.com/\r\nHeader:x'])
def test_private_or_unsafe_page_address_rejected(url):
    with pytest.raises(ContentReadError):public_url(url)


def test_query_and_fragment_are_never_fetched():
    clean,host=public_url('https://example.com/path?token=PRIVATE#secret')
    assert clean=='https://example.com/path' and host=='example.com'
    assert public_url('https://faß.de/')[1]=='xn--fa-hia.de'


@pytest.mark.parametrize('address',['127.0.0.1','10.0.0.1','169.254.169.254','::1','fd00::1','192.0.2.1'])
def test_resolved_private_addresses_rejected(monkeypatch,address):
    monkeypatch.setattr('socket.getaddrinfo',lambda *a,**k:[(0,0,0,'',(address,443))])
    with pytest.raises(ContentReadError):resolve_public('example.com')


def test_mixed_public_private_dns_cannot_pass(monkeypatch):
    monkeypatch.setattr('socket.getaddrinfo',lambda *a,**k:[(0,0,0,'',('1.1.1.1',443)),(0,0,0,'',('127.0.0.1',443))])
    with pytest.raises(ContentReadError):resolve_public('example.com')


def test_html_scripts_and_styles_are_not_context():
    result=extract_text(b'<h1>Public heading</h1><script>PRIVATE script</script><style>PRIVATE CSS</style><p>Visible text</p>','text/html')
    assert 'Public heading' in result['text'] and 'PRIVATE' not in result['text']


@pytest.mark.parametrize('data,kind',[(b'x'*262145,'text/plain'),(b'\x00binary','text/plain'),(b'\xff','text/plain'),(b'binary','application/octet-stream')],ids=['too-large','binary','invalid-utf8','unsupported-type'])
def test_large_binary_or_invalid_text_refused(data,kind):
    with pytest.raises(ContentReadError):extract_text(data,kind)


def test_model_boundary_is_structured_private_and_tool_free():
    client=model_fixture(codes=['malicious_url'])
    result=write_narrative({'scan':{'severity':'Critical'}},client=client,model='test-model',evidence_codes=('malicious_url',))
    call=client.responses.create.call_args.kwargs
    assert call['store'] is False and call['text']['format']['strict'] is True and 'tools' not in call
    assert 'untrusted' in call['instructions'] and result['source']=='openai'


@pytest.mark.parametrize('value',['','not-json','{"summary":"short"}'])
def test_bad_model_response_is_not_a_report(value):
    client=model_fixture();client.responses.create.return_value.output_text=value
    with pytest.raises(ReportGenerationError):write_narrative({},client=client,model='test-model')


def test_invented_evidence_and_private_links_are_rejected():
    for client in [model_fixture(codes=['invented_attack']),model_fixture(summary='Visit https://private.example/ to finish the investigation.')]:
        with pytest.raises(ReportGenerationError):write_narrative({},client=client,model='test-model')


@pytest.mark.parametrize('kind,period',[('weekly','2026-09-28'),('monthly','2026-09')])
def test_closed_calendar_ranges(kind,period):
    start,end=period_bounds(kind,period,now=datetime(2026,10,5,tzinfo=timezone.utc))
    assert start.tzinfo and end<=datetime(2026,10,5,tzinfo=timezone.utc)


@pytest.mark.parametrize('kind,period',[('weekly','2026-10-05'),('weekly','2026-09-29'),('monthly','2026-10'),('monthly','2026-13'),('weekly','2026-02-30')])
def test_open_invalid_or_non_monday_periods_refused(kind,period):
    with pytest.raises(ValueError):period_bounds(kind,period,now=datetime(2026,10,5,tzinfo=timezone.utc))


def test_previous_periods_roll_over_year_and_week():
    assert completed_periods(datetime(2027,1,1,tzinfo=timezone.utc))==[('weekly','2026-12-21'),('monthly','2026-12')]


def test_explanation_preserves_risk_and_discards_raw_detail(system):
    client,app,headers,_=system
    app.state.intelligence_llm_client=model_fixture(codes=['malicious_url']);app.state.intelligence_model='test-model'
    record=scan(client)
    response=client.post('/api/intelligence/scans/'+record['id']+'/explain',headers=headers['hasan'],json={'language':'ar'})
    assert response.status_code==200,response.text
    assert response.json()['review_required'] is True
    prompt=app.state.intelligence_llm_client.responses.create.call_args.kwargs['input']
    assert 'PRIVATE' not in prompt and 'private.example' not in prompt
    assert client.get('/api/scans/'+record['id'],headers=headers['hasan']).json()['severity']==record['severity']
    repeat=client.post('/api/intelligence/scans/'+record['id']+'/explain',headers=headers['hasan'],json={'language':'ar'})
    assert repeat.json()['id']==response.json()['id']
    assert app.state.intelligence_llm_client.responses.create.call_count==1


def test_content_requires_consent_before_reading(system):
    client,app,headers,_=system;record=scan(client)
    result=client.post('/api/intelligence/scans/'+record['id']+'/explain',headers=headers['hasan'],json={'page_url':'https://example.com/'})
    assert result.status_code==422


def test_missing_model_is_explicit_unavailable(system,monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY',raising=False);monkeypatch.delenv('OPENAI_MODEL',raising=False)
    client,app,headers,_=system;record=scan(client)
    result=client.post('/api/intelligence/scans/'+record['id']+'/explain',headers=headers['hasan'],json={})
    assert result.status_code==503 and result.headers['cache-control']=='no-store'
    with app.state.session_factory() as db:assert not db.scalar(select(ExplanationRecord))


def test_foreign_file_and_page_context_cannot_be_attached(system):
    client,app,headers,_=system;record=scan(client)
    app.state.intelligence_llm_client=model_fixture();app.state.intelligence_model='test-model'
    for context in [{'page_url':'https://example.com/'},{'file_base64':base64.b64encode(b'hello').decode()}]:
        result=client.post('/api/intelligence/scans/'+record['id']+'/explain',headers=headers['hasan'],json={**context,'consent_content':True})
        assert result.status_code==422
    assert app.state.intelligence_llm_client.responses.create.call_count==0


def test_normal_user_cannot_read_other_users_explanations_or_reports(roles):
    client,app,headers,_=roles
    record=scan(client)
    assert client.get('/api/intelligence/scans/'+record['id'],headers=headers['normal_user']).status_code==404
    assert client.get('/api/intelligence/reports',headers=headers['normal_user']).status_code==403
    assert client.post('/api/intelligence/reports/generate',headers=headers['manager'],json={'kind':'weekly','period':'2026-09-28'}).status_code==403


def test_period_archive_includes_all_alerts_and_summaries_without_raw_targets(system):
    client,app,headers,_=system;record=scan(client)
    start=datetime(2026,9,28,tzinfo=timezone.utc);end=start+timedelta(days=7)
    with app.state.session_factory() as db:
        source=db.get(Scan,record['id']);source.created_at=start
        first=db.scalar(select(Alert).where(Alert.scan_id==source.id));first.created_at=start
        db.add(Alert(scan_id=source.id,severity='Critical',status='open',message='PRIVATE target',created_at=end))
        db.add(ExplanationRecord(scan_id=source.id,language='en',context_digest='x'*64,context_scope='reputation_evidence_only',narrative={'summary':'A reviewed explanation without personal identifiers.','evidence_codes':['malicious_url'],'recommendations':['Review evidence']},created_at=start))
        db.commit()
        totals,archive=aggregate_period(db,start,end)
        assert totals['alerts_total']==1 and totals['explanations_total']==1
        assert 'PRIVATE' not in json.dumps(archive) and len(archive['alerts'])==1
        payload=PeriodRequest(kind='weekly',period='2026-09-28')
        model=model_fixture();report=prepare_period_report(db,payload,client=model,model='test-model',now=end)
        assert report.stats['archive']['alerts']==archive['alerts']
        assert prepare_period_report(db,payload,client=model,model='test-model',now=end).id==report.id
        assert model.responses.create.call_count==1


def test_anonymous_intelligence_routes_are_protected(system):
    client,_,_,_=system
    assert client.get('/api/intelligence/reports').status_code==401
    assert client.post('/api/intelligence/scans/unknown/explain',json={}).status_code==401


def test_matching_text_file_reaches_model_only_with_consent_and_is_not_persisted(system):
    import hashlib
    client,app,headers,_=system
    text=b'Public sample text with token=TOPSECRET and contact=person@example.com.'
    created=client.post('/api/scans',headers={'X-Ingest-Token':'governance-ingest'},json={
        'device_id':'text-lab','device_name':'Lab','target_kind':'download','target':hashlib.sha256(text).hexdigest(),
        'signals':[{'code':'malicious_file_hash','status':'detected'}]}).json()
    app.state.intelligence_llm_client=model_fixture(codes=['malicious_file_hash']);app.state.intelligence_model='test-model'
    response=client.post('/api/intelligence/scans/'+created['id']+'/explain',headers=headers['hasan'],json={
        'consent_content':True,'file_base64':base64.b64encode(text).decode()})
    assert response.status_code==200,response.text
    prompt=app.state.intelligence_llm_client.responses.create.call_args.kwargs['input']
    assert 'TOPSECRET' not in prompt and 'person@example.com' not in prompt
    with app.state.session_factory() as db:
        saved=db.scalar(select(ExplanationRecord));assert saved.context_scope=='selected_text_file'
        assert 'Public sample text' not in json.dumps(saved.narrative)


def test_generation_throttle_and_failed_model_do_not_persist_fake_explanation(system):
    client,app,headers,_=system;record=scan(client)
    app.state.intelligence_llm_client=model_fixture();app.state.intelligence_model='test-model'
    app.state.intelligence_llm_client.responses.create.return_value.status='incomplete'
    for i in range(3):
        response=client.post('/api/intelligence/scans/'+record['id']+'/explain',headers=headers['hasan'],json={})
        assert response.status_code==502
    assert client.post('/api/intelligence/scans/'+record['id']+'/explain',headers=headers['hasan'],json={}).status_code==429
    with app.state.session_factory() as db:assert not db.scalar(select(ExplanationRecord))


def test_reader_does_not_follow_redirects_and_rejects_compression(monkeypatch):
    from alba_security.content_reader import read_public_page
    monkeypatch.setattr('alba_security.content_reader.resolve_public',lambda host:['1.1.1.1'])
    for status,encoding in [(302,'identity'),(200,'gzip')]:
        response=SimpleNamespace(status=status,getheader=lambda name,default=None:encoding if name=='Content-Encoding' else default)
        connection=Mock();connection.getresponse.return_value=response
        monkeypatch.setattr('alba_security.content_reader.PinnedHTTPS',lambda host,address:connection)
        with pytest.raises(ContentReadError):read_public_page('https://example.com/')
        assert connection.request.call_count==1 and connection.close.call_count==1


def test_explanation_deletion_follows_source_scan(system):
    from sqlalchemy import delete
    client,app,headers,_=system;record=scan(client)
    with app.state.session_factory() as db:
        db.add(ExplanationRecord(scan_id=record['id'],language='en',context_digest='x'*64,narrative={},context_scope='reputation_evidence_only'))
        db.commit()
        # Remove existing evidence children before the scan, just as retention does.
        from alba_security.models import Finding,SecurityEvent
        for model in [Alert,Finding,SecurityEvent]:db.execute(delete(model).where(model.scan_id==record['id']))
        db.execute(delete(Scan).where(Scan.id==record['id']));db.commit()
        assert not db.scalar(select(ExplanationRecord))
