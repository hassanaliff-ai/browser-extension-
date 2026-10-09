-- Run through a server-side driver with bound parameters. Database credentials
-- must never be stored in the Chrome extension. Reporting windows are UTC,
-- inclusive at :start_utc and exclusive at :end_utc.

-- Extension / dashboard: recent scan and stored risk evidence.
SELECT * FROM extsecure_scan_history
WHERE created_at >= :start_utc AND created_at < :end_utc
ORDER BY created_at DESC, scan_id DESC LIMIT :row_limit;

-- Investigation: findings attached to one authorized scan.
SELECT signal_code, title, points, severity, created_at FROM findings
WHERE scan_id = :scan_id ORDER BY points DESC, id;

-- Domain inventory with no query strings or credentials.
SELECT d.hostname, COUNT(s.id) AS scans, MAX(s.created_at) AS last_scan
FROM domains d LEFT JOIN scans s ON s.domain_id=d.id
GROUP BY d.id, d.hostname ORDER BY last_scan DESC NULLS LAST;

-- Weekly report (Monday-based UTC weeks).
SELECT * FROM extsecure_weekly_statistics
WHERE period_start_utc >= :start_utc AND period_start_utc < :end_utc
ORDER BY period_start_utc;

-- Monthly report; Unknown is shown separately from confirmed low risk.
SELECT * FROM extsecure_monthly_statistics
WHERE period_start_utc >= :start_utc AND period_start_utc < :end_utc
ORDER BY period_start_utc;

-- Alert and incident monitoring: aggregate tables separately to avoid
-- multiplying counts when a scan has several findings or history events.
SELECT severity, status, COUNT(*) FROM alerts
WHERE created_at >= :start_utc AND created_at < :end_utc
GROUP BY severity,status;

-- Audit records are append-only for the application role.
SELECT id, area, reference, actor, action, created_at FROM governance_audit
WHERE created_at >= :start_utc AND created_at < :end_utc
ORDER BY created_at DESC, id DESC LIMIT :row_limit;
