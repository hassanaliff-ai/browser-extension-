"""Learn unusual daily scan activity from earlier aggregate observations."""
from datetime import timedelta
import hashlib
import json
import math
from sqlalchemy import case, func, select
from alba_security.models import Scan

MODEL_VERSION = 'monthly-isolation-forest-v1'


def daily_counts(db, start, end):
    """Group on the database; do not load individual browsing identifiers."""
    timestamp = func.timezone('UTC', Scan.created_at) if db.get_bind().dialect.name == 'postgresql' else Scan.created_at
    day = func.date(timestamp)
    rows = db.execute(select(day, func.count(),
        func.sum(case((Scan.severity.in_(['High', 'Critical']), 1), else_=0)),
        func.sum(case((Scan.severity == 'Unknown', 1), else_=0)))
        .where(Scan.created_at >= start, Scan.created_at < end).group_by(day))
    found = {str(date): (int(total), int(high), int(unknown)) for date, total, high, unknown in rows}
    return [{'date': (start + timedelta(days=i)).date().isoformat(),
             **dict(zip(['scans', 'high_risk', 'unknown'], found.get((start + timedelta(days=i)).date().isoformat(), (0, 0, 0))))}
            for i in range((end - start).days)]


def features(rows):
    return [[math.log1p(r['scans']), r['high_risk'] / r['scans'] if r['scans'] else 0,
             r['unknown'] / r['scans'] if r['scans'] else 0] for r in rows]


def analyze_month(db, year, month):
    # Lazy import avoids a circular dependency with the report generator.
    from alba_security.reports import _month_bounds
    start, end = _month_bounds(year, month)
    training_start = start - timedelta(days=90)
    training = daily_counts(db, training_start, start)
    observed = daily_counts(db, start, end)
    active_days = sum(r['scans'] > 0 for r in training)
    result = {'model': 'Isolation Forest', 'model_version': MODEL_VERSION,
              'period': f'{year:04d}-{month:02d}', 'training_start': training_start.isoformat(),
              'training_end_exclusive': start.isoformat(), 'training_days': len(training),
              'active_training_days': active_days, 'features': ['log_scan_count', 'high_risk_fraction', 'unknown_fraction'],
              'training_digest': hashlib.sha256(json.dumps(training, sort_keys=True).encode()).hexdigest(),
              'random_seed': 42, 'status': 'insufficient_history', 'unusual_days': [], 'daily_results': [],
              'limitation': 'Unusual activity is a review signal, not proof of a threat or a breach. Sparse data, retention, policy changes and changes in scanning coverage affect the result.'}
    if active_days < 30 or len({tuple(r) for r in features(training)}) < 3:
        result['reason'] = 'At least 30 active historical days and three distinct feature observations are required.'
        return result
    try:
        from sklearn import __version__
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return {**result, 'status': 'unavailable', 'reason': 'Install the declared scikit-learn dependency.'}
    model = IsolationForest(n_estimators=100, contamination='auto', random_state=42, n_jobs=1)
    model.fit(features(training))
    predictions = model.predict(features(observed))
    margins = model.decision_function(features(observed))
    result.update(status='ready', library_version=__version__)
    for row, prediction, margin in zip(observed, predictions, margins):
        evidence = {**row, 'unusual': bool(prediction == -1), 'decision_margin': round(float(margin), 6)}
        result['daily_results'].append(evidence)
        if evidence['unusual']:
            result['unusual_days'].append(evidence)
    return result
