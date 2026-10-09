-- ExtSecure PostgreSQL schema. Generated from the application models.

-- Provision a dedicated database first; execute this only as the schema owner.

BEGIN;


CREATE TABLE account_registration_enrollments (
	token_hash VARCHAR(64) NOT NULL,
	username VARCHAR(120) NOT NULL,
	password_hash TEXT NOT NULL,
	totp_encrypted TEXT NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	failed_attempts INTEGER NOT NULL,
	PRIMARY KEY (token_hash),
	UNIQUE (username)
)

;


CREATE TABLE admin_auth_state (
	id VARCHAR(32) NOT NULL,
	failed_attempts INTEGER NOT NULL,
	locked_until TIMESTAMP WITH TIME ZONE,
	last_totp_counter INTEGER NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE admin_invitations (
	id VARCHAR(36) NOT NULL,
	token_hash VARCHAR(64) NOT NULL,
	username VARCHAR(120) NOT NULL,
	author VARCHAR(120) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	consumed_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	UNIQUE (token_hash)
)

;


CREATE TABLE admin_login_challenges (
	token_hash VARCHAR(64) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	consumed_at TIMESTAMP WITH TIME ZONE,
	username VARCHAR(120),
	PRIMARY KEY (token_hash)
)

;


CREATE TABLE admin_overrides (
	id VARCHAR(36) NOT NULL,
	kind VARCHAR(6) NOT NULL,
	match_key VARCHAR(253) NOT NULL,
	target_display VARCHAR(253) NOT NULL,
	reason TEXT NOT NULL,
	active BOOLEAN NOT NULL,
	created_by VARCHAR(120) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE,
	deactivated_by VARCHAR(120),
	deactivated_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id)
)

;


CREATE TABLE admin_sessions (
	token_hash VARCHAR(64) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	revoked_at TIMESTAMP WITH TIME ZONE,
	username VARCHAR(120),
	PRIMARY KEY (token_hash)
)

;


CREATE TABLE ai_period_reports (
	id VARCHAR(36) NOT NULL,
	kind VARCHAR(8) NOT NULL,
	period VARCHAR(10) NOT NULL,
	language VARCHAR(2) NOT NULL,
	stats JSON NOT NULL,
	narrative JSON NOT NULL,
	subject VARCHAR(150) NOT NULL,
	body TEXT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_ai_period_report UNIQUE (kind, period, language)
)

;


CREATE TABLE detection_evaluations (
	id VARCHAR(36) NOT NULL,
	dataset_version VARCHAR(80) NOT NULL,
	policy_version VARCHAR(60) NOT NULL,
	actor VARCHAR(120) NOT NULL,
	results JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE devices (
	id VARCHAR(100) NOT NULL,
	name VARCHAR(120) NOT NULL,
	first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE domains (
	id VARCHAR(36) NOT NULL,
	hostname VARCHAR(253) NOT NULL,
	first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_domains_hostname_nonempty CHECK (length(hostname) > 0)
)

;


CREATE TABLE evaluation_datasets (
	version VARCHAR(80) NOT NULL,
	digest VARCHAR(64) NOT NULL,
	fixtures JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (version)
)

;


CREATE TABLE file_reputation_cache (
	sha256 VARCHAR(64) NOT NULL,
	verdict VARCHAR(16) NOT NULL,
	malicious_count INTEGER NOT NULL,
	suspicious_count INTEGER NOT NULL,
	checked_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (sha256)
)

;


CREATE TABLE governance_audit (
	id VARCHAR(36) NOT NULL,
	area VARCHAR(24) NOT NULL,
	reference VARCHAR(100) NOT NULL,
	actor VARCHAR(120) NOT NULL,
	action VARCHAR(50) NOT NULL,
	details JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE governance_state (
	id VARCHAR(24) NOT NULL,
	version INTEGER NOT NULL,
	data JSON NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE incident_workflow_rules (
	id VARCHAR(36) NOT NULL,
	name VARCHAR(120) NOT NULL,
	enabled BOOLEAN NOT NULL,
	priority INTEGER NOT NULL,
	revision INTEGER NOT NULL,
	settings JSON NOT NULL,
	author VARCHAR(120) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE inventory_policy (
	id SERIAL NOT NULL,
	enrollment_required BOOLEAN NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE monthly_reports (
	id VARCHAR(36) NOT NULL,
	period VARCHAR(7) NOT NULL,
	stats JSON NOT NULL,
	subject VARCHAR(200) NOT NULL,
	body TEXT NOT NULL,
	summary_source VARCHAR(30) NOT NULL,
	generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	sent_at TIMESTAMP WITH TIME ZONE,
	delivery_outcomes JSON NOT NULL,
	status VARCHAR(12) NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_monthly_report_status CHECK (status IN ('draft', 'sent', 'failed'))
)

;


CREATE TABLE registered_administrators (
	username VARCHAR(120) NOT NULL,
	password_hash TEXT NOT NULL,
	totp_encrypted TEXT NOT NULL,
	status VARCHAR(20) NOT NULL,
	role VARCHAR(30) NOT NULL,
	approved_by VARCHAR(120),
	approved_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (username)
)

;


CREATE TABLE security_control_reviews (
	id VARCHAR(36) NOT NULL,
	control VARCHAR(24) NOT NULL,
	reference_type VARCHAR(24) NOT NULL,
	reference_id VARCHAR(36) NOT NULL,
	outcome VARCHAR(24) NOT NULL,
	ground_truth VARCHAR(16) NOT NULL,
	evidence TEXT NOT NULL,
	actor VARCHAR(120) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE security_navigation_evidence (
	id VARCHAR(64) NOT NULL,
	actor VARCHAR(120) NOT NULL,
	device_id VARCHAR(100),
	target_fingerprint VARCHAR(64) NOT NULL,
	outcome VARCHAR(16) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE security_policy_revisions (
	id VARCHAR(36) NOT NULL,
	base_version VARCHAR(60) NOT NULL,
	author VARCHAR(120) NOT NULL,
	reviewer VARCHAR(120),
	status VARCHAR(20) NOT NULL,
	reason TEXT NOT NULL,
	review_reason TEXT,
	policy JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE usability_records (
	id VARCHAR(36) NOT NULL,
	actor VARCHAR(120) NOT NULL,
	task VARCHAR(200) NOT NULL,
	category VARCHAR(30) NOT NULL,
	outcome VARCHAR(24) NOT NULL,
	observation TEXT NOT NULL,
	status VARCHAR(24) NOT NULL,
	revision INTEGER NOT NULL,
	verification TEXT,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE virustotal_quota (
	id INTEGER NOT NULL,
	minute_start TIMESTAMP WITH TIME ZONE NOT NULL,
	minute_count INTEGER NOT NULL,
	day_start TIMESTAMP WITH TIME ZONE NOT NULL,
	day_count INTEGER NOT NULL,
	blocked_until TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id)
)

;


CREATE TABLE website_access_requests (
	id VARCHAR(36) NOT NULL,
	requester VARCHAR(120) NOT NULL,
	target VARCHAR(2048) NOT NULL,
	reason TEXT NOT NULL,
	status VARCHAR(20) NOT NULL,
	decision VARCHAR(20),
	reviewer VARCHAR(120),
	review_reason TEXT,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	revision INTEGER NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE website_access_whitelist (
	id VARCHAR(36) NOT NULL,
	target VARCHAR(2048) NOT NULL,
	reviewer VARCHAR(120) NOT NULL,
	reason TEXT NOT NULL,
	active BOOLEAN NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE admin_override_audit (
	id VARCHAR(36) NOT NULL,
	override_id VARCHAR(36) NOT NULL,
	action VARCHAR(16) NOT NULL,
	actor VARCHAR(120) NOT NULL,
	details JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(override_id) REFERENCES admin_overrides (id)
)

;


CREATE TABLE device_registrations (
	device_id VARCHAR(100) NOT NULL,
	ip_address VARCHAR(45) NOT NULL,
	operating_system VARCHAR(32) NOT NULL,
	blocked BOOLEAN NOT NULL,
	revision INTEGER NOT NULL,
	added_by VARCHAR(120) NOT NULL,
	pairing_hash VARCHAR(64),
	pairing_expires TIMESTAMP WITH TIME ZONE,
	chrome_extension_id VARCHAR(100),
	detected_os VARCHAR(32),
	last_sync TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (device_id),
	FOREIGN KEY(device_id) REFERENCES devices (id),
	UNIQUE (pairing_hash)
)

;


CREATE TABLE extensions (
	id VARCHAR(36) NOT NULL,
	device_id VARCHAR(100) NOT NULL,
	extension_key VARCHAR(100) NOT NULL,
	name VARCHAR(160) NOT NULL,
	version VARCHAR(40),
	first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_extension_device_key UNIQUE (device_id, extension_key),
	FOREIGN KEY(device_id) REFERENCES devices (id)
)

;


CREATE TABLE inventory_browser_credentials (
	token_hash VARCHAR(64) NOT NULL,
	device_id VARCHAR(100) NOT NULL,
	revoked BOOLEAN NOT NULL,
	PRIMARY KEY (token_hash),
	FOREIGN KEY(device_id) REFERENCES devices (id)
)

;


CREATE TABLE inventory_device_enrollments (
	device_id VARCHAR(100) NOT NULL,
	status VARCHAR(16) NOT NULL,
	requested_by VARCHAR(120) NOT NULL,
	ip_source VARCHAR(24) NOT NULL,
	PRIMARY KEY (device_id),
	FOREIGN KEY(device_id) REFERENCES devices (id)
)

;


CREATE TABLE chrome_extension_observations (
	extension_id VARCHAR(36) NOT NULL,
	present BOOLEAN NOT NULL,
	last_sync TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (extension_id),
	FOREIGN KEY(extension_id) REFERENCES extensions (id)
)

;


CREATE TABLE scans (
	id VARCHAR(36) NOT NULL,
	device_id VARCHAR(100) NOT NULL,
	extension_id VARCHAR(36),
	domain_id VARCHAR(36),
	risk_policy_version VARCHAR(80),
	override_id VARCHAR(36),
	target_kind VARCHAR(16) NOT NULL,
	target_fingerprint VARCHAR(64) NOT NULL,
	target_display VARCHAR(180) NOT NULL,
	signals JSON NOT NULL,
	score INTEGER,
	severity VARCHAR(12) NOT NULL,
	completeness VARCHAR(12) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_scans_score_range CHECK (score IS NULL OR (score >= 0 AND score <= 100)),
	CONSTRAINT ck_scans_severity CHECK (severity IN ('Unknown','Low','Medium','High','Critical')),
	CONSTRAINT ck_scans_completeness CHECK (completeness IN ('complete','partial','unknown')),
	CONSTRAINT ck_scans_target_kind CHECK (target_kind IN ('url','ip','hash','download','extension')),
	FOREIGN KEY(device_id) REFERENCES devices (id),
	FOREIGN KEY(extension_id) REFERENCES extensions (id),
	FOREIGN KEY(domain_id) REFERENCES domains (id),
	FOREIGN KEY(override_id) REFERENCES admin_overrides (id)
)

;


CREATE TABLE ai_scan_explanations (
	id VARCHAR(36) NOT NULL,
	scan_id VARCHAR(36) NOT NULL,
	language VARCHAR(2) NOT NULL,
	context_digest VARCHAR(64) NOT NULL,
	narrative JSON NOT NULL,
	context_scope VARCHAR(40) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_ai_explanation UNIQUE (scan_id, language, context_digest),
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
)

;


CREATE TABLE alerts (
	id VARCHAR(36) NOT NULL,
	scan_id VARCHAR(36) NOT NULL,
	severity VARCHAR(12) NOT NULL,
	message VARCHAR(300) NOT NULL,
	status VARCHAR(16) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(scan_id) REFERENCES scans (id)
)

;


CREATE TABLE findings (
	id VARCHAR(36) NOT NULL,
	scan_id VARCHAR(36) NOT NULL,
	device_id VARCHAR(100) NOT NULL,
	extension_id VARCHAR(36),
	signal_code VARCHAR(60) NOT NULL,
	title VARCHAR(160) NOT NULL,
	detail TEXT,
	points INTEGER NOT NULL,
	severity VARCHAR(12) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(scan_id) REFERENCES scans (id),
	FOREIGN KEY(device_id) REFERENCES devices (id),
	FOREIGN KEY(extension_id) REFERENCES extensions (id)
)

;


CREATE TABLE incident_cases (
	id VARCHAR(36) NOT NULL,
	scan_id VARCHAR(36) NOT NULL,
	title VARCHAR(160) NOT NULL,
	assignee VARCHAR(120) NOT NULL,
	status VARCHAR(20) NOT NULL,
	resolution TEXT,
	revision INTEGER NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(scan_id) REFERENCES scans (id)
)

;


CREATE TABLE personal_scan_ownership (
	scan_id VARCHAR(36) NOT NULL,
	username VARCHAR(120) NOT NULL,
	PRIMARY KEY (scan_id),
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
)

;


CREATE TABLE security_events (
	id VARCHAR(36) NOT NULL,
	event_type VARCHAR(50) NOT NULL,
	severity VARCHAR(12) NOT NULL,
	message VARCHAR(300) NOT NULL,
	scan_id VARCHAR(36) NOT NULL,
	device_id VARCHAR(100) NOT NULL,
	extension_id VARCHAR(36),
	details JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(scan_id) REFERENCES scans (id),
	FOREIGN KEY(device_id) REFERENCES devices (id),
	FOREIGN KEY(extension_id) REFERENCES extensions (id)
)

;


CREATE TABLE incident_case_notes (
	id VARCHAR(36) NOT NULL,
	case_id VARCHAR(36) NOT NULL,
	author VARCHAR(120) NOT NULL,
	body TEXT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(case_id) REFERENCES incident_cases (id)
)

;


CREATE TABLE incident_workflow_links (
	case_id VARCHAR(36) NOT NULL,
	rule_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (case_id),
	FOREIGN KEY(case_id) REFERENCES incident_cases (id),
	FOREIGN KEY(rule_id) REFERENCES incident_workflow_rules (id)
)

;


CREATE TABLE incident_workflow_notices (
	id VARCHAR(64) NOT NULL,
	case_id VARCHAR(36) NOT NULL,
	rule_id VARCHAR(36) NOT NULL,
	recipient VARCHAR(120) NOT NULL,
	phase VARCHAR(24) NOT NULL,
	details JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	acknowledged_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	FOREIGN KEY(case_id) REFERENCES incident_cases (id),
	FOREIGN KEY(rule_id) REFERENCES incident_workflow_rules (id)
)

;

CREATE INDEX ix_admin_overrides_match ON admin_overrides (kind, match_key, active);

CREATE UNIQUE INDEX ix_domains_hostname ON domains (hostname);

CREATE INDEX ix_domains_last_seen ON domains (last_seen);

CREATE INDEX ix_governance_audit_area ON governance_audit (area);

CREATE UNIQUE INDEX ix_monthly_reports_period ON monthly_reports (period);

CREATE INDEX ix_security_control_reviews_control ON security_control_reviews (control);

CREATE INDEX ix_security_control_reviews_reference_id ON security_control_reviews (reference_id);

CREATE INDEX ix_security_navigation_evidence_actor ON security_navigation_evidence (actor);

CREATE INDEX ix_security_navigation_evidence_created_at ON security_navigation_evidence (created_at);

CREATE INDEX ix_website_access_requests_requester ON website_access_requests (requester);

CREATE INDEX ix_website_access_requests_status ON website_access_requests (status);

CREATE INDEX ix_website_access_requests_target ON website_access_requests (target);

CREATE INDEX ix_website_access_whitelist_target ON website_access_whitelist (target);

CREATE INDEX ix_admin_override_audit_created ON admin_override_audit (created_at);

CREATE INDEX ix_admin_override_audit_override_id ON admin_override_audit (override_id);

CREATE INDEX ix_extensions_device_id ON extensions (device_id);

CREATE INDEX ix_inventory_browser_credentials_device_id ON inventory_browser_credentials (device_id);

CREATE INDEX ix_scans_created_at ON scans (created_at);

CREATE INDEX ix_scans_device_id ON scans (device_id);

CREATE INDEX ix_scans_domain_created ON scans (domain_id, created_at);

CREATE INDEX ix_scans_domain_id ON scans (domain_id);

CREATE INDEX ix_scans_extension_id ON scans (extension_id);

CREATE INDEX ix_scans_override_id ON scans (override_id);

CREATE INDEX ix_scans_severity_created ON scans (severity, created_at);

CREATE INDEX ix_ai_scan_explanations_created_at ON ai_scan_explanations (created_at);

CREATE INDEX ix_ai_scan_explanations_scan_id ON ai_scan_explanations (scan_id);

CREATE INDEX ix_alerts_scan_id ON alerts (scan_id);

CREATE INDEX ix_alerts_status_created ON alerts (status, created_at);

CREATE INDEX ix_findings_created_at ON findings (created_at);

CREATE INDEX ix_findings_device_id ON findings (device_id);

CREATE INDEX ix_findings_extension_id ON findings (extension_id);

CREATE INDEX ix_findings_scan_id ON findings (scan_id);

CREATE INDEX ix_incident_cases_scan_id ON incident_cases (scan_id);

CREATE INDEX ix_personal_scan_ownership_username ON personal_scan_ownership (username);

CREATE INDEX ix_events_created_at ON security_events (created_at);

CREATE INDEX ix_security_events_device_id ON security_events (device_id);

CREATE INDEX ix_security_events_extension_id ON security_events (extension_id);

CREATE INDEX ix_security_events_scan_id ON security_events (scan_id);

CREATE INDEX ix_incident_case_notes_case_id ON incident_case_notes (case_id);

CREATE INDEX ix_incident_workflow_links_rule_id ON incident_workflow_links (rule_id);

CREATE INDEX ix_incident_workflow_notices_case_id ON incident_workflow_notices (case_id);

CREATE INDEX ix_incident_workflow_notices_recipient ON incident_workflow_notices (recipient);

CREATE VIEW extsecure_risk_results AS SELECT id AS scan_id, device_id, domain_id, target_kind, score,
 severity, completeness, risk_policy_version, override_id, created_at FROM scans;

CREATE VIEW extsecure_scan_history AS SELECT s.id AS scan_id, s.device_id, d.name AS device_name,
 s.extension_id, h.hostname, s.target_kind, s.score, s.severity, s.completeness,
 s.risk_policy_version, s.created_at FROM scans s JOIN devices d ON d.id=s.device_id
 LEFT JOIN domains h ON h.id=s.domain_id;

CREATE VIEW extsecure_alert_history AS SELECT a.id AS alert_id, a.scan_id, s.device_id, a.severity,
 a.status, a.message, a.created_at FROM alerts a JOIN scans s ON s.id=a.scan_id;

CREATE VIEW extsecure_daily_statistics AS SELECT
 date_trunc('day',created_at AT TIME ZONE 'UTC') AS period_start_utc,
 count(*) AS total_scans, count(DISTINCT device_id) AS unique_devices,
 count(DISTINCT domain_id) AS unique_domains,
 count(*) FILTER (WHERE severity IN ('High','Critical')) AS high_risk_scans,
 count(*) FILTER (WHERE severity='Unknown') AS unknown_scans
 FROM scans GROUP BY 1;

CREATE VIEW extsecure_weekly_statistics AS SELECT
 date_trunc('week',created_at AT TIME ZONE 'UTC') AS period_start_utc,
 count(*) AS total_scans, count(DISTINCT device_id) AS unique_devices,
 count(DISTINCT domain_id) AS unique_domains,
 count(*) FILTER (WHERE severity IN ('High','Critical')) AS high_risk_scans,
 count(*) FILTER (WHERE severity='Unknown') AS unknown_scans
 FROM scans GROUP BY 1;

CREATE VIEW extsecure_monthly_statistics AS SELECT
 date_trunc('month',created_at AT TIME ZONE 'UTC') AS period_start_utc,
 count(*) AS total_scans, count(DISTINCT device_id) AS unique_devices,
 count(DISTINCT domain_id) AS unique_domains,
 count(*) FILTER (WHERE severity IN ('High','Critical')) AS high_risk_scans,
 count(*) FILTER (WHERE severity='Unknown') AS unknown_scans
 FROM scans GROUP BY 1;

COMMIT;
