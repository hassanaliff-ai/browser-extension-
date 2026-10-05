"""Ten focused checks for ML, report delivery, UI and administrator 2FA."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import json
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from alba_security.models import Base, Device, Scan
from alba_security.monthly_ml import analyze_month
from alba_security.notifications import NotificationSettings
from alba_security.report_job import prepare_monthly_report, dispatch_monthly_report, MonthlyReportRecord
from tests.alba.test_governance import system  # noqa: F401
from tests.test_dashboard import http, app, assert_clean, button, response  # noqa: F401

START = datetime(2026, 9, 1, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        session.add(Device(id='ml-device', name='PRIVATE device name'))
        session.commit()
        yield session
    engine.dispose()


def seed(db, varied=True):
    for i in range(90):
        for j in range(5 + i % 5 if varied else 5):
            add(db, START - timedelta(days=90-i),
                'High' if varied and j == 0 and i % 3 == 0 else
                'Unknown' if varied and j == 1 and i % 4 == 0 else 'Low')
    db.commit()


def add(db, date, severity='Low'):
    db.add(Scan(device_id='ml-device', target_kind='url', target_fingerprint='a'*64,
                target_display='PRIVATE.example', signals=[], score=None if severity == 'Unknown' else 80,
                severity=severity, completeness='unknown' if severity == 'Unknown' else 'complete', created_at=date))


def test_01_empty_history_reports_insufficient_data(db):
    result = analyze_month(db, 2026, 9)
    assert result['status'] == 'insufficient_history' and not result['daily_results']


def test_02_constant_history_does_not_produce_misleading_model(db):
    seed(db, varied=False)
    assert analyze_month(db, 2026, 9)['status'] == 'insufficient_history'


def test_03_target_and_future_month_never_enter_training(db):
    seed(db)
    before = analyze_month(db, 2026, 9)
    add(db, START, 'Critical')
    add(db, START + timedelta(days=40), 'Critical')
    db.commit()
    after = analyze_month(db, 2026, 9)
    assert before['training_digest'] == after['training_digest']
    assert after['training_end_exclusive'] == START.isoformat()
    assert sum(r['scans'] for r in after['daily_results']) == 1


def test_04_fixed_seed_gives_reproducible_results(db):
    seed(db)
    assert analyze_month(db, 2026, 9) == analyze_month(db, 2026, 9)


def test_05_large_threat_volume_spike_is_flagged_for_review(db):
    seed(db)
    for _ in range(100):
        add(db, START + timedelta(days=9), 'Critical')
    db.commit()
    result = analyze_month(db, 2026, 9)
    assert result['status'] == 'ready'
    spike = next(r for r in result['daily_results'] if r['date'] == '2026-09-10')
    assert spike['unusual'] and spike['decision_margin'] < 0
    assert 'not proof' in result['limitation']


def test_06_model_outputs_exclude_browsing_and_device_identifiers(db):
    seed(db)
    result = analyze_month(db, 2026, 9)
    assert 'PRIVATE' not in json.dumps(result)
    assert 'ml-device' not in json.dumps(result)
    assert result['features'][-1] == 'unknown_fraction'


def test_07_llm_and_saved_delivery_include_same_ml_snapshot(db):
    seed(db)
    prompts, deliveries = [], []
    def generate(**kwargs):
        prompts.append(kwargs['input'])
        return SimpleNamespace(output_text='Review unusual activity alongside the verified monthly statistics.')
    fake = SimpleNamespace(responses=SimpleNamespace(create=generate))
    report = prepare_monthly_report(db, 2026, 9, llm_client=fake, model='mock-model')
    assert report.stats['machine_learning']['status'] == 'ready'
    assert 'machine_learning' in prompts[0] and 'PRIVATE' not in prompts[0]
    settings = NotificationSettings(smtp_host='smtp.invalid', smtp_from='reports@example.invalid', admin_emails=('admin@example.invalid',))
    delivered = dispatch_monthly_report(db, report, settings=settings, email_sender=lambda *args: deliveries.append(args))
    assert delivered.status == 'sent' and 'Machine-learning activity review' in deliveries[0][2]
    assert prepare_monthly_report(db, 2026, 9, llm_client=fake, model='mock-model').id == report.id
    dispatch_monthly_report(db, report, settings=settings, email_sender=lambda *args: deliveries.append(args))
    assert len(prompts) == len(deliveries) == 1
    assert db.scalar(select(MonthlyReportRecord)).stats['machine_learning'] == report.stats['machine_learning']


def test_08_ml_api_requires_completed_two_factor_login(system):
    client, _, headers, _ = system
    route = '/api/reports/monthly/ml?year=2026&month=9'
    assert client.get(route).status_code == 401
    challenge = client.post('/api/admin/login', json={'username':'hasan','password':'primary-test-password'}).json()['challenge_token']
    assert client.get(route, headers={'Authorization':'Bearer '+challenge}).status_code == 401
    assert client.get(route, headers={'X-Ingest-Token':'governance-ingest'}).status_code == 401
    assert client.get(route, headers=headers['hasan']).status_code == 200


def test_09_ml_api_rejects_incomplete_month_and_invalid_date(system):
    client, _, headers, _ = system
    assert client.get('/api/reports/monthly/ml?year=2100&month=12', headers=headers['hasan']).status_code == 422
    assert client.get('/api/reports/monthly/ml?year=2026&month=13', headers=headers['hasan']).status_code == 422


def test_10_monthly_ui_runs_ml_and_shows_insufficient_history(http):
    original = http[0].side_effect
    def get(url, **kwargs):
        if '/api/reports/monthly/ml?' in url:
            period = f"{int(url.split('year=')[1].split('&')[0]):04d}-{int(url.split('month=')[1]):02d}"
            return response({'period':period,'status':'insufficient_history','reason':'At least 30 active historical days are required.'})
        return original(url, **kwargs)
    http[0].side_effect = get
    instance = app(True, 'Monthly reports')
    button(instance, 'Run monthly ML analysis').click().run()
    assert_clean(instance)
    assert any('30 active historical days' in r.value for r in instance.warning)
    assert not http[1].called
