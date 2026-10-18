-- migrate:up
CREATE TABLE IF NOT EXISTS user_security_feedback (
	id VARCHAR(36) NOT NULL, 
	scan_id VARCHAR(36) NOT NULL, 
	reporter VARCHAR(120) NOT NULL, 
	category VARCHAR(30) NOT NULL, 
	message TEXT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	outcome VARCHAR(24), 
	review_note TEXT, 
	reviewed_by VARCHAR(120), 
	reviewed_at TIMESTAMP WITH TIME ZONE, 
	revision INTEGER NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_feedback_scan_reporter UNIQUE (scan_id, reporter), 
	CONSTRAINT ck_feedback_category CHECK (category IN ('suspicious_result','challenge_warning')), 
	CONSTRAINT ck_feedback_status CHECK (status IN ('pending','reviewed')), 
	CONSTRAINT ck_feedback_outcome CHECK (outcome IS NULL OR outcome IN ('threat_confirmed','false_positive','inconclusive')), 
	CONSTRAINT ck_feedback_revision CHECK (revision >= 1), 
	CONSTRAINT ck_feedback_message CHECK (length(message) BETWEEN 10 AND 2000), 
	CONSTRAINT ck_feedback_review CHECK ((status='pending' AND outcome IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL AND review_note IS NULL) OR (status='reviewed' AND outcome IS NOT NULL AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND review_note IS NOT NULL)), 
	FOREIGN KEY(scan_id) REFERENCES scans (id)
);
CREATE INDEX IF NOT EXISTS ix_feedback_status_created ON user_security_feedback (status, created_at);
CREATE INDEX IF NOT EXISTS ix_user_security_feedback_reporter ON user_security_feedback (reporter);
CREATE INDEX IF NOT EXISTS ix_user_security_feedback_scan_id ON user_security_feedback (scan_id);
-- migrate:down
DROP TABLE user_security_feedback;
