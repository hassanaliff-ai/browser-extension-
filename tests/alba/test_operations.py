"""Real authenticated API workflows; no live email or threat services."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from alba_security.governance import GovernanceAudit, IncidentCase
from alba_security.models import Alert, Scan, SecurityEvent, utc_now
from alba_security.operations import (ControlReview, NavigationEvidence, WorkflowNotice, WorkflowRule,
                                      effectiveness, run_workflows, latency)
from alba_security.website_access import WebsiteRequest
from tests.alba.test_governance import system, scan  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401


def rule(client, header, **changes):
    payload = {'name': 'High risk investigation', 'enabled': True, 'priority': 20,
               'minimum_severity': 'High', 'target_kind': 'any', 'auto_create': True,
               'assignee': 'hasan', 'notify_reviewer': True, 'reviewer': 'reviewer',
               'escalate_after_hours': 24, 'escalate_to': 'hasan',
               'reason': 'Assign and review confirmed high risk scans', **changes}
    response = client.post('/api/workflow/rules', headers=header, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_new_routes_require_two_factor_and_roles(roles):
    client, _, headers, _ = roles
    for path in ('workflow/rules', 'workflow/notifications', 'controls/effectiveness', 'controls/reviews'):
        assert client.get('/api/'+path).status_code == 401
        assert client.get('/api/'+path, headers=headers['normal_user']).status_code == 403
        assert client.get('/api/'+path, headers=headers['head_administrator']).status_code == 200
    assert client.get('/api/workflow/rules',headers=headers['manager']).status_code == 403
    assert client.get('/api/workflow/notifications',headers=headers['manager']).status_code == 200
    for path in ('workflow/rules', 'workflow/run', 'controls/reviews'):
        assert client.post('/api/'+path, headers=headers['manager'], json={}).status_code == 403
    assert client.post('/api/controls/navigation',headers=headers['normal_user'],json={}).status_code == 422


def test_disabled_by_default_and_unknown_scans_never_create_cases(system):
    client, _, headers, _ = system
    rule(client,headers['hasan'],enabled=False)
    scan(client)
    assert client.get('/api/cases',headers=headers['hasan']).json() == []
    rule(client,headers['hasan'])
    scan(client,status='unknown')
    assert client.get('/api/cases',headers=headers['hasan']).json() == []


def test_first_matching_rule_creates_one_case_and_durable_notices(system):
    client, app, headers, _ = system
    rule(client,headers['hasan'],priority=50,assignee='hasan')
    winner=rule(client,headers['hasan'],priority=1,assignee='reviewer')
    result=scan(client)
    cases=client.get('/api/cases',headers=headers['hasan']).json()
    assert len(cases)==1 and cases[0]['scan_id']==result['id'] and cases[0]['assignee']=='reviewer'
    notices=client.get('/api/workflow/notifications',headers=headers['hasan']).json()
    assert {n['phase'] for n in notices} == {'assigned','review_requested'}
    assert all(n['rule_id']==winner['id'] for n in notices)
    run_workflows(app)
    assert len(client.get('/api/workflow/notifications',headers=headers['hasan']).json())==2


def test_exception_suppression_does_not_create_an_automatic_case(system):
    client, _, headers, _ = system
    rule(client,headers['hasan'])
    response=client.post('/api/overrides',headers=headers['hasan'],json={
        'kind':'domain','target':'private.example','reason':'Approved isolated laboratory exception'})
    assert response.status_code == 201, response.text
    result=scan(client)
    assert result['override_id']
    assert client.get('/api/cases',headers=headers['hasan']).json()==[]


def test_deadline_ignores_notes_escalates_once_and_respects_revision(system):
    client, app, headers, _ = system
    rule(client,headers['hasan'],assignee='reviewer')
    scan(client)
    row=client.get('/api/cases',headers=headers['hasan']).json()[0]
    with app.state.session_factory() as db:
        case=db.get(IncidentCase,row['id']);case.created_at=utc_now()-timedelta(hours=25);db.commit()
    client.post('/api/cases/'+row['id']+'/notes',headers=headers['reviewer'],json={'body':'Recent evidence note does not postpone the deadline.'})
    assert run_workflows(app)['escalated']==1
    current=client.get('/api/cases/'+row['id'],headers=headers['hasan']).json()
    assert current['assignee']=='hasan' and current['revision']==2
    assert run_workflows(app)['escalated']==0
    stale=client.post('/api/cases/'+row['id']+'/status',headers=headers['hasan'],json={
        'expected_revision':1,'status':'investigating','assignee':'reviewer','reason':'Attempt an outdated investigation update'})
    assert stale.status_code==409


def test_resolved_cases_stay_resolved_reopening_starts_new_deadline(system):
    client, app, headers, _ = system
    rule(client,headers['hasan'])
    scan(client)
    row=client.get('/api/cases',headers=headers['hasan']).json()[0]
    route='/api/cases/'+row['id']+'/status'
    for revision,status in [(1,'investigating'),(2,'resolved')]:
        assert client.post(route,headers=headers['hasan'],json={'expected_revision':revision,'status':status,
            'assignee':'hasan','reason':'Investigated the evidence and recorded outcome'}).status_code==200
    with app.state.session_factory() as db:
        db.get(IncidentCase,row['id']).created_at=utc_now()-timedelta(days=2);db.commit()
    assert run_workflows(app)['escalated']==0
    assert client.post(route,headers=headers['hasan'],json={'expected_revision':3,'status':'open','assignee':'hasan',
        'reason':'Reopen the incident after new evidence'}).status_code==200
    assert run_workflows(app)['escalated']==0
    assert run_workflows(app,now=utc_now()+timedelta(hours=25))['escalated']==1


def test_disabled_rule_stops_escalation_and_updates_require_current_revision(system):
    client, app, headers, _ = system
    saved=rule(client,headers['hasan'])
    scan(client)
    payload={k:v for k,v in saved.items() if k not in {'id','revision','author','created_at'}}
    payload.update(enabled=False,expected_revision=1,reason='Pause this automation while reviewing the policy')
    url='/api/workflow/rules/'+saved['id']+'/update'
    assert client.post(url,headers=headers['hasan'],json=payload).status_code==200
    assert client.post(url,headers=headers['hasan'],json=payload).status_code==409
    assert run_workflows(app,now=utc_now()+timedelta(days=2))['escalated']==0


@pytest.mark.parametrize('change',[{'assignee':'missing'},{'reviewer':'missing'}, {'escalate_to':'missing'},
                                   {'escalate_after_hours':0},{'escalate_after_hours':True},
                                   {'enabled':'true'},{'minimum_severity':'Unknown'},{'priority':101}])
def test_invalid_workflow_inputs_are_rejected(system,change):
    client, _, headers, _ = system
    payload={'name':'Invalid rule fixture','assignee':'hasan','reviewer':'hasan','escalate_to':'hasan',
             'reason':'Test strict input and identity validation',**change}
    assert client.post('/api/workflow/rules',headers=headers['hasan'],json=payload).status_code==422


def test_manual_assignment_is_preserved_and_notifications_are_private(roles):
    client, app, headers, _ = roles
    saved=rule(client,headers['head_administrator'],auto_create=False,assignee='administrator',reviewer='manager')
    result=scan(client)
    case=client.post('/api/cases',headers=headers['head_administrator'],json={'scan_id':result['id'],
        'title':'Manual investigator assignment','assignee':'administrator'}).json()
    run_workflows(app)
    assert client.get('/api/cases/'+case['id'],headers=headers['head_administrator']).json()['assignee']=='administrator'
    inbox=client.get('/api/workflow/notifications',headers=headers['manager']).json()
    assert len(inbox)==1 and inbox[0]['recipient']=='manager' and inbox[0]['rule_id']==saved['id']
    assert client.post('/api/workflow/notifications/'+inbox[0]['id']+'/acknowledge',headers=headers['manager'],json={}).status_code==200
    assert client.post('/api/workflow/notifications/'+inbox[0]['id']+'/acknowledge',headers=headers['manager'],json={}).status_code==200


def test_empty_metrics_do_not_claim_perfect_controls(system):
    client, _, headers, _ = system
    data=client.get('/api/controls/effectiveness',headers=headers['hasan']).json()
    assert all(r['effectiveness_percent'] is None for r in data['controls'])
    assert data['alerts']['response_time']['median_seconds'] is None
    assert data['detection']['labelled_scans']==0


def test_navigation_reports_deduplicate_and_discard_private_urls(system):
    client, app, headers, _ = system
    body={'event_id':'a'*64,'target':'https://example.com/private?secret=NEVER_STORE#token','outcome':'blocked'}
    response=client.post('/api/controls/navigation',headers=headers['hasan'],json=body)
    assert response.status_code==201 and response.json()['recorded']
    assert not client.post('/api/controls/navigation',headers=headers['hasan'],json=body).json()['recorded']
    data=client.get('/api/controls/effectiveness',headers=headers['hasan']).json()
    assert data['blocking']['blocked_reports']==1 and data['blocking']['source']=='extension_reported'
    with app.state.session_factory() as db:
        row=db.scalar(select(NavigationEvidence))
        assert len(row.target_fingerprint)==64 and not hasattr(row,'target')
    body['target']='https://username:password@example.com/'
    body['event_id']='b'*64
    assert client.post('/api/controls/navigation',headers=headers['hasan'],json=body).status_code==422


def test_ground_truth_reviews_expose_false_positives_false_negatives_and_unknown(system):
    client, _, headers, _ = system
    high=scan(client);low=scan(client,status='clear');unknown=scan(client,status='unknown')
    for source,label,outcome in [(high,'benign','unnecessary'),(low,'threat','missed'),(unknown,'threat','inconclusive')]:
        response=client.post('/api/controls/reviews',headers=headers['hasan'],json={'control':'blocking',
            'reference_type':'scan','reference_id':source['id'],'outcome':outcome,'ground_truth':label,
            'evidence':'Independent laboratory evidence supports this review label.'})
        assert response.status_code==201,response.text
    data=client.get('/api/controls/effectiveness',headers=headers['hasan']).json()
    assert data['detection']=={'labelled_scans':3,'assessed_scans':2,'unknown_scans':1,'missed_warnings':1,'unnecessary_warnings':1}
    # Latest correction replaces a label; it does not count the same scan twice.
    client.post('/api/controls/reviews',headers=headers['hasan'],json={'control':'blocking','reference_type':'scan',
        'reference_id':high['id'],'outcome':'effective','ground_truth':'threat',
        'evidence':'Additional independently verified evidence corrects the previous label.'})
    data=client.get('/api/controls/effectiveness',headers=headers['hasan']).json()
    assert data['detection']['unnecessary_warnings']==0
    assert next(r for r in data['controls'] if r['control']=='blocking')['effectiveness_percent']==50


def test_unrelated_or_missing_references_cannot_be_reviewed(system):
    client, _, headers, _ = system
    result=scan(client)
    payload={'control':'approvals','reference_type':'scan','reference_id':result['id'],'outcome':'effective',
             'evidence':'An independent reference must relate to the selected control.'}
    assert client.post('/api/controls/reviews',headers=headers['hasan'],json=payload).status_code==422
    payload.update(control='exceptions')
    assert client.post('/api/controls/reviews',headers=headers['hasan'],json=payload).status_code==422
    payload.update(control='blocking',reference_id='missing')
    assert client.post('/api/controls/reviews',headers=headers['hasan'],json=payload).status_code==404


def test_response_times_repeat_detection_and_window_boundaries(system):
    client, app, headers, _ = system
    first=scan(client);scan(client)
    now=utc_now();start=now-timedelta(hours=2)
    with app.state.session_factory() as db:
        alert=db.scalar(select(Alert).where(Alert.scan_id==first['id']));alert.created_at=start
        db.add(SecurityEvent(event_type='alert_status_changed',severity='Critical',message='Acknowledged fixture',
            scan_id=first['id'],device_id='lab-device',details={'alert_id':alert.id,'status':'acknowledged'},
            created_at=start+timedelta(minutes=10)))
        request=WebsiteRequest(requester='hasan',target='https://example.com/',reason='Synthetic evaluation fixture',
            status='approved',decision='temporary',reviewer='hasan',created_at=start,expires_at=now+timedelta(days=1))
        db.add(request);db.flush()
        db.add(GovernanceAudit(area='website_access',reference=request.id,actor='hasan',action='approved',
            created_at=start+timedelta(minutes=20),details={}))
        db.commit()
        data=effectiveness(db,30,now)
        assert data['alerts']['response_time']['median_seconds']==600
        assert data['approvals']['response_time']['median_seconds']==1200
        assert data['incidents']['repeated_detections']==1
        old=db.get(Scan,first['id']);old.created_at=now-timedelta(days=31);db.commit()
        assert effectiveness(db,30,now)['incidents']['repeated_detections']==0


def test_latency_statistics_use_nearest_rank_and_exclude_negative_clock_samples():
    assert latency([-1,0,30,60])=={'samples':3,'median_seconds':30,'p95_seconds':60}


def test_background_runner_starts_with_monitoring_lifespan(system):
    client, app, headers, _ = system
    data=client.get('/api/workflow/rules',headers=headers['hasan']).json()
    assert data['runner']['interval_seconds']==60
    assert data['runner']['status']=='ready' and data['runner']['last_run']


def test_navigation_observations_follow_existing_retention_policy(system):
    client, app, headers, _ = system
    with app.state.session_factory() as db:
        db.add(NavigationEvidence(id='c'*64,actor='hasan',target_fingerprint='d'*64,outcome='blocked',
            created_at=utc_now()-timedelta(days=100)))
        db.commit()
    preview=client.get('/api/privacy/retention-preview',headers=headers['hasan']).json()
    assert preview['eligible_navigation_observations']==1
    response=client.post('/api/privacy/retention-apply',headers=headers['hasan'],json={
        'expected_revision':preview['revision'],'confirm':True})
    assert response.status_code==200,response.text
    with app.state.session_factory() as db:
        assert db.get(NavigationEvidence,'c'*64) is None


def test_manager_cannot_acknowledge_another_reviewers_notice(roles):
    client, _, headers, _ = roles
    rule(client,headers['head_administrator'],reviewer='administrator')
    scan(client)
    inbox=client.get('/api/workflow/notifications',headers=headers['head_administrator']).json()
    assert client.get('/api/workflow/notifications',headers=headers['manager']).json()==[]
    assert client.post('/api/workflow/notifications/'+inbox[0]['id']+'/acknowledge',
        headers=headers['manager'],json={}).status_code==403


def test_revoked_investigator_does_not_prevent_escalation_to_active_administrator(system):
    from alba_security.registration import RegisteredAdmin
    client, app, headers, _ = system
    rule(client,headers['hasan'],assignee='reviewer')
    scan(client)
    with app.state.session_factory() as db:
        case=db.scalar(select(IncidentCase));case.created_at=utc_now()-timedelta(days=2)
        db.get(RegisteredAdmin,'reviewer').status='disabled';db.commit()
    assert run_workflows(app)['escalated']==1


@pytest.mark.anyio
async def test_parent_api_lifespan_starts_and_stops_mounted_workflow_runner(monkeypatch):
    from contextlib import asynccontextmanager
    from fastapi import FastAPI
    import main
    calls=[]
    class FakeVirusTotal:
        def __init__(self,*_):pass
        async def aclose(self):calls.append('vt_closed')
    @asynccontextmanager
    async def nested_lifespan(app):
        calls.append('workflow_started')
        yield
        calls.append('workflow_stopped')
    monkeypatch.setattr(main,'VirusTotalClient',FakeVirusTotal)
    parent=FastAPI();parent.state.monitoring_app=FastAPI(lifespan=nested_lifespan)
    async with main.lifespan(parent):
        assert calls==['workflow_started']
    assert calls==['workflow_started','workflow_stopped','vt_closed']


def test_pausing_rule_preserves_settings_when_an_operator_is_revoked(system):
    from alba_security.registration import RegisteredAdmin
    client, app, headers, _ = system
    saved=rule(client,headers['hasan'],assignee='reviewer',reviewer='reviewer')
    with app.state.session_factory() as db:
        db.get(RegisteredAdmin,'reviewer').status='disabled';db.commit()
    payload={k:v for k,v in saved.items() if k not in {'id','revision','author','created_at'}}
    payload.update(enabled=False,expected_revision=1,reason='Pause the workflow after the reviewer account was revoked')
    path='/api/workflow/rules/'+saved['id']+'/update'
    assert client.post(path,headers=headers['hasan'],json=payload).status_code==200
    payload.update(enabled=True,expected_revision=2)
    assert client.post(path,headers=headers['hasan'],json=payload).status_code==422


def test_operations_readiness_is_private_and_distinguishes_stopped_runner(roles):
    client, app, headers, _ = roles
    path='/api/operations/status'
    assert client.get(path).status_code==401
    assert client.get(path,headers=headers['normal_user']).status_code==403
    response=client.get(path,headers=headers['manager'])
    assert response.status_code==200 and response.headers['cache-control']=='no-store'
    data=response.json()
    assert data['api_version']=='0.4.1' and data['status']=='ready'
    assert data['workflow']['running'] and data['workflow']['interval_seconds']==60
    assert {'case_escalation','control_effectiveness'}.issubset(data['capabilities'])
    assert data['notifications']['channel']=='in_app'
    app.state.workflow_running=False
    assert client.get(path,headers=headers['head_administrator']).json()['status']=='degraded'
    app.state.workflow_running=True


def test_mounted_feature_discovery_reports_support_without_exposing_private_state(system):
    from fastapi.testclient import TestClient
    import main
    client, monitor, headers, _ = system
    parent=main.create_app();parent.state.monitoring_app=monitor
    parent.mount('/monitor',monitor)
    # The fixture already starts the monitoring lifespan; do not start it twice.
    mounted=TestClient(parent)
    try:
        response=mounted.get('/extension/capabilities')
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        data=response.json()
        assert data['monitoring_available'] and data['monitoring_base']=='/monitor/api'
        assert data['monitoring_docs']=='/monitor/docs' and data['workflow_runner_started']
        assert data['api_version']=='0.4.1' and 'case_escalation' in data['capabilities']
        private=mounted.get('/monitor/api/operations/status',headers=headers['hasan'])
        assert private.status_code==200 and private.json()['workflow']['running']
        assert 'hasan' not in response.text and 'token' not in response.text
    finally:
        mounted.close()
