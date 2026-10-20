"""Email retirement preserves reports, signed webhooks, and local protection."""
import hashlib
import hmac
from types import SimpleNamespace
import pytest
from sqlalchemy import inspect
from alba_security import notifications as module
from alba_security.notifications import NotificationSettings, send_high_severity_alert
from alba_security.report_job import MonthlyReportRecord


def test_removed_email_environment_cannot_trigger_delivery(monkeypatch):
    for key, value in {'SMTP_HOST':'invalid', 'SMTP_PORT':'not-an-int', 'SMTP_PASSWORD':'fixture',
                       'EMAIL_PROVIDER':'gmail_oauth', 'BREVO_API_KEY':'fixture'}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('ALERT_WEBHOOK_URLS', raising=False)
    monkeypatch.delenv('ALERT_WEBHOOK_URL', raising=False)
    assert send_high_severity_alert(alert_id='a', scan_id='s', severity='Critical', message='private') == [
        {'channel':'webhook', 'status':'skipped', 'reason':'not_configured'}]
    assert not hasattr(module, '_deliver_email') and not hasattr(module, 'send_monthly_report')


def test_report_model_has_no_email_delivery_fields():
    assert {'sent_at', 'delivery_outcomes'}.isdisjoint(MonthlyReportRecord.__table__.columns.keys())


def test_real_webhook_adapter_is_signed_private_and_bounded(monkeypatch):
    captured = {}
    class Client:
        def __init__(self, **kwargs): captured['options'] = kwargs
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, *, content, headers):
            captured.update(url=url, body=content, headers=headers)
            return SimpleNamespace(raise_for_status=lambda: None)
    monkeypatch.setattr(module.httpx, 'Client', Client)
    result = send_high_severity_alert(alert_id='a', scan_id='s', severity='Critical', score=95,
        message='PRIVATE URL', settings=NotificationSettings(webhook_urls=('https://hooks.example/notify',), webhook_secret='fixture', timeout_seconds=4))
    assert result == [{'channel':'webhook','status':'sent','destination_index':1}]
    assert captured['options'] == {'timeout':4,'follow_redirects':False}
    assert b'PRIVATE' not in captured['body']
    digest = hmac.new(b'fixture', captured['body'], hashlib.sha256).hexdigest()
    assert captured['headers']['X-Alba-Signature'] == 'sha256=' + digest
    assert captured['headers']['Idempotency-Key'] == 'a'


def test_repeated_webhook_destinations_delivered_once():
    calls=[]
    outcomes=send_high_severity_alert(alert_id='a',scan_id='s',severity='High',message='',
        settings=NotificationSettings(webhook_urls=('https://hooks.example/a',' https://hooks.example/a ')),
        webhook_sender=lambda *args:calls.append(args))
    assert len(calls)==len(outcomes)==1


@pytest.mark.parametrize('severity',['Low','Medium','Unknown'])
def test_non_high_results_do_not_notify(severity):
    assert send_high_severity_alert(alert_id='a',scan_id='s',severity=severity,message='') == []


def test_webhook_failure_is_sanitized():
    def fail(*args): raise TimeoutError('PRIVATE token')
    result=send_high_severity_alert(alert_id='a',scan_id='s',severity='High',message='',
        settings=NotificationSettings(webhook_urls=('https://hooks.example/a',)),webhook_sender=fail)
    assert result==[{'channel':'webhook','status':'failed','destination_index':1,'error_type':'TimeoutError'}]


def test_existing_sqlite_reports_upgrade_without_losing_content():
    from sqlalchemy import create_engine, text
    from alba_security.schema import ensure_schema
    engine=create_engine('sqlite://')
    with engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE monthly_reports (id VARCHAR(36) PRIMARY KEY, period VARCHAR(7), stats JSON NOT NULL, subject TEXT, body TEXT, summary_source VARCHAR(30), generated_at TIMESTAMP, status VARCHAR(12), sent_at TIMESTAMP, delivery_outcomes JSON NOT NULL)")
        db.exec_driver_sql("INSERT INTO monthly_reports VALUES ('r','2026-09','{}','Saved subject','Saved body','local','2026-10-01','failed',NULL,'[]')")
    ensure_schema(engine)
    columns={c['name'] for c in inspect(engine).get_columns('monthly_reports')}
    assert not columns & {'sent_at','delivery_outcomes'}
    with engine.connect() as db:
        row=db.execute(text('SELECT subject,body,status FROM monthly_reports')).one()
        assert tuple(row)==('Saved subject','Saved body','draft')
    engine.dispose()
