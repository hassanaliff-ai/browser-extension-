-- Additive threat containment. No existing evidence or approvals are removed.
-- migrate:up
CREATE TABLE IF NOT EXISTS security_threat_blocks (
 id VARCHAR(80) PRIMARY KEY,
 kind VARCHAR(16) NOT NULL,
 fingerprint VARCHAR(64) NOT NULL,
 scan_id VARCHAR(36) NOT NULL REFERENCES scans(id),
 target_display VARCHAR(180) NOT NULL,
 severity VARCHAR(12) NOT NULL CONSTRAINT ck_threat_block_severity CHECK (severity IN ('High','Critical')),
 active BOOLEAN NOT NULL DEFAULT TRUE,
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_security_threat_blocks_fingerprint ON security_threat_blocks(fingerprint);
CREATE INDEX IF NOT EXISTS ix_security_threat_blocks_scan_id ON security_threat_blocks(scan_id);
-- migrate:down
-- The rollback runner permits disposable extsecure_test_ databases only.
DROP TABLE IF EXISTS security_threat_blocks;
