-- Run through a server-side driver with bound parameters. Database credentials
-- must never be stored in the Chrome extension. Reporting windows are UTC,
-- inclusive at :start_utc and exclusive at :end_utc.

-- Extension / dashboard: recent scan and stored risk evidence. Validate
-- :row_limit as 1..500 in the backend; :device_id can be NULL for authorized
-- organization-wide queries. Never rely on the SQL parameter as authorization.
SELECT scan_id, device_id, device_name, extension_id, hostname, target_kind,
       score, severity, completeness, risk_policy_version, created_at
FROM extsecure_scan_history
WHERE created_at >= :start_utc AND created_at < :end_utc
  AND (CAST(:device_id AS VARCHAR) IS NULL OR device_id = :device_id)
ORDER BY created_at DESC, scan_id DESC LIMIT :row_limit;

-- Next page: stable cursor ordering also handles scans with equal timestamps.
-- Supply both cursor fields from the final row of the previous page and retain
-- the same authorized device and time filters.
SELECT scan_id,device_id,severity,score,completeness,created_at
FROM extsecure_scan_history
WHERE created_at >= :start_utc AND created_at < :end_utc
  AND (CAST(:device_id AS VARCHAR) IS NULL OR device_id = :device_id)
  AND (created_at,scan_id) < (:before_utc,:before_scan_id)
ORDER BY created_at DESC,scan_id DESC LIMIT :row_limit;

-- Investigation: findings attached to one authorized scan.
SELECT signal_code, title, points, severity, created_at FROM findings
WHERE scan_id = :scan_id ORDER BY points DESC, id;

-- Domain inventory with no query strings or credentials.
SELECT d.hostname, COUNT(s.id) AS scans, MAX(s.created_at) AS last_scan,
       MAX(s.score) AS highest_score,
       COUNT(*) FILTER (WHERE s.severity IN ('High','Critical')) AS high_risk_scans,
       COUNT(*) FILTER (WHERE s.severity='Unknown') AS unknown_scans
FROM domains d JOIN scans s ON s.domain_id=d.id
WHERE s.created_at >= :start_utc AND s.created_at < :end_utc
  AND (CAST(:device_id AS VARCHAR) IS NULL OR s.device_id = :device_id)
GROUP BY d.id, d.hostname
ORDER BY highest_score DESC NULLS LAST, last_scan DESC, d.id LIMIT :row_limit;

-- Investigation: accurate evidence counts, without joining child rows together.
SELECT scan_id,device_id,severity,completeness,risk_policy_version,
       finding_count,alert_count,event_count,created_at
FROM extsecure_scan_evidence WHERE scan_id=:scan_id;

-- Weekly report (Monday-based UTC weeks).
-- These views contain whole period buckets. For an arbitrary partial-period
-- window, use report_totals_query(start,end) instead of summing whole buckets.
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
