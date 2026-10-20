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


@pytest.mark.parametrize("generation_fails", [False, True])
def test_scheduler_saves_reports_and_closes_connections(monkeypatch, capsys, generation_fails):
    disposed=[]
    engine=SimpleNamespace(dispose=lambda:disposed.append(True))
    class FakeSession:
        def __init__(self,*args,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
    def generate(*args):
        if generation_fails: raise RuntimeError('model unavailable')
        return SimpleNamespace(period='2025-12',status='draft')
    monkeypatch.setattr('sys.argv',['monthly_runner','--year','2025','--month','12'])
    monkeypatch.setenv('DATABASE_URL','sqlite://')
    monkeypatch.setattr(monthly_runner,'create_engine',lambda *a,**kw:engine)
    monkeypatch.setattr(monthly_runner,'ensure_schema',lambda *a:None)
    monkeypatch.setattr(monthly_runner,'Session',FakeSession)
    monkeypatch.setattr(monthly_runner,'prepare_monthly_report',generate)
    if generation_fails:
        with pytest.raises(RuntimeError): monthly_runner.main()
    else:
        monthly_runner.main()
        assert '2025-12: draft' in capsys.readouterr().out
    assert disposed==[True]
