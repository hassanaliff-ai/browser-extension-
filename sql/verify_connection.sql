-- Run inside the extsecure database in pgAdmin Query Tool.
-- Read-only proof of the connection and stored security evidence.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT current_database() AS database, current_schema() AS schema,
       current_user AS database_role, inet_server_port() AS server_port;
SELECT 'scans' AS record_type, count(*) AS saved_records FROM scans
UNION ALL SELECT 'devices', count(*) FROM devices
UNION ALL SELECT 'extensions', count(*) FROM extensions
UNION ALL SELECT 'domains', count(*) FROM domains
UNION ALL SELECT 'findings', count(*) FROM findings
UNION ALL SELECT 'alerts', count(*) FROM alerts
UNION ALL SELECT 'security_events', count(*) FROM security_events
UNION ALL SELECT 'personal_scan_ownership', count(*) FROM personal_scan_ownership
UNION ALL SELECT 'incident_cases', count(*) FROM incident_cases
UNION ALL SELECT 'governance_audit', count(*) FROM governance_audit;
SELECT scan_id,device_name,target_kind,severity,score,created_at
FROM extsecure_scan_history ORDER BY created_at DESC LIMIT 20;
SELECT * FROM extsecure_scan_evidence ORDER BY created_at DESC LIMIT 20;
COMMIT;
