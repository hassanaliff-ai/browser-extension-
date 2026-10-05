"""Scheduler-facing period selection and honest process status."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from alba_security import monthly_runner


@pytest.mark.parametrize("now, expected", [
    (datetime(2027, 1, 1, tzinfo=timezone.utc), (2026, 12)),
    (datetime(2024, 3, 1, tzinfo=timezone.utc), (2024, 2)),
    # UTC is still September even if local time has entered October.
    (datetime(2026, 10, 1, 1, tzinfo=timezone(timedelta(hours=3))), (2026, 8)),
])
def test_previous_completed_month_uses_utc(now, expected):
    assert monthly_runner.completed_report_period(None, None, now=now) == expected


@pytest.mark.parametrize("year, month", [(2026, None), (None, 9), (2026, 0), (2026, 13), (1999, 1), (2026, 10), (2027, 1)])
def test_incomplete_invalid_and_open_periods_are_rejected(year, month):
    with pytest.raises(ValueError):
        monthly_runner.completed_report_period(year, month, now=datetime(2026, 10, 10, tzinfo=timezone.utc))


@pytest.mark.parametrize("delivery_status, prepare_only, exit_code", [
    ("sent", False, None),
    ("failed", False, 1),
    ("draft", True, None),
])
def test_scheduler_receives_failure_exit_code_and_connections_close(
    monkeypatch, capsys, delivery_status, prepare_only, exit_code,
):
    disposed, dispatched = [], []
    engine = SimpleNamespace(dispose=lambda: disposed.append(True))
    report = SimpleNamespace(period="2025-12", status="draft", delivery_outcomes=[])

    class FakeSession:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    def dispatch(_db, record):
        dispatched.append(True)
        record.status = delivery_status
        record.delivery_outcomes = [{"channel": "email", "status": "sent" if delivery_status == "sent" else "skipped"}]
        return record

    argv = ["monthly_runner", "--year", "2025", "--month", "12"]
    if prepare_only:
        argv.append("--prepare-only")
    monkeypatch.setattr("sys.argv", argv)
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setattr(monthly_runner, "create_engine", lambda *_a, **_k: engine)
    monkeypatch.setattr(monthly_runner, "ensure_schema", lambda *_: None)
    monkeypatch.setattr(monthly_runner, "Session", FakeSession)
    monkeypatch.setattr(monthly_runner, "prepare_monthly_report", lambda *_: report)
    monkeypatch.setattr(monthly_runner, "dispatch_monthly_report", dispatch)
    if exit_code:
        with pytest.raises(SystemExit) as error:
            monthly_runner.main()
        assert error.value.code == exit_code
    else:
        monthly_runner.main()
    assert disposed == [True]
    assert bool(dispatched) is not prepare_only
    assert f"2025-12: {delivery_status}" in capsys.readouterr().out
