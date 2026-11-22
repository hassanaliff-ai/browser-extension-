"""Expose bounded, sanitized status from the automatic report scheduler."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re

KSA = timezone(timedelta(hours=3))
LOG_PATH = Path(__file__).resolve().parents[2] / '.private' / 'automatic-reports.jsonl'
VALID_STATUS = {'generated', 'already_saved', 'failed'}
VALID_STAGES = {'local_ai', 'database', 'generation'}


def _read_attempts(path):
    try:
        with path.open('rb') as stream:
            stream.seek(0, 2)
            length = stream.tell()
            stream.seek(max(0, length - 128 * 1024))
            lines = stream.read(128 * 1024).splitlines()
    except OSError:
        return []
    attempts = []
    for line in lines:
        try:
            row = json.loads(line)
            kind, status = row['kind'], row['status']
            if kind not in {'weekly', 'monthly'} or status not in VALID_STATUS:
                continue
            at = datetime.fromisoformat(row['at'])
            if at.tzinfo is None:
                continue
            period = row.get('period')
            pattern = r'20\d{2}-\d{2}' if kind == 'monthly' else r'20\d{2}-\d{2}-\d{2}'
            stage = row.get('stage')
            if not isinstance(stage, str) or stage not in VALID_STAGES:
                stage = None
            attempts.append({'kind':kind, 'status':status, 'at':at.astimezone(timezone.utc).isoformat(),
                             'stage':stage if status == 'failed' else None,
                             'period':period if isinstance(period, str) and re.fullmatch(pattern, period) else None})
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
    return sorted(attempts, key=lambda row: row['at'], reverse=True)


def report_schedule_status(enabled, *, now=None, path=None):
    local_now = (now or datetime.now(timezone.utc)).astimezone(KSA)
    today = local_now.replace(hour=9, minute=0, second=0, microsecond=0)
    weekly = today + timedelta(days=(6 - today.weekday()) % 7)
    if weekly <= local_now:
        weekly += timedelta(days=7)
    monthly = today.replace(day=1)
    if monthly <= local_now:
        monthly = (monthly + timedelta(days=32)).replace(day=1)
    retry = today.replace(minute=10)
    if retry <= local_now:
        retry += timedelta(days=1)
    attempts = _read_attempts(path or LOG_PATH)
    result = {}
    for kind, next_run in [('weekly', weekly), ('monthly', monthly)]:
        selection = [row for row in attempts if row['kind'] == kind]
        result[kind] = {'next_scheduled_at':next_run.isoformat() if enabled else None,
                        'last_attempt':next(iter(selection), None),
                        'last_success':next((row for row in selection if row['status'] != 'failed'), None)}
    result['monthly']['next_recovery_at'] = retry.isoformat() if enabled else None
    return result
