-- migrate:up
ALTER TABLE chrome_extension_observations ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE chrome_extension_observations ADD COLUMN IF NOT EXISTS may_disable BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE chrome_extension_observations ADD COLUMN IF NOT EXISTS may_enable BOOLEAN NOT NULL DEFAULT TRUE;
CREATE TABLE IF NOT EXISTS inventory_extension_controls (
 extension_id VARCHAR(36) PRIMARY KEY REFERENCES extensions(id),
 desired VARCHAR(16) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'pending',
 revision INTEGER NOT NULL DEFAULT 1,
 error VARCHAR(300),
 CONSTRAINT ck_extension_control_desired CHECK (desired IN ('enabled','disabled','blocked','removed')),
 CONSTRAINT ck_extension_control_status CHECK (status IN ('pending','applied','failed')),
 CONSTRAINT ck_extension_control_revision CHECK (revision >= 1)
);
-- migrate:down
DROP TABLE inventory_extension_controls;
ALTER TABLE chrome_extension_observations DROP COLUMN enabled;
ALTER TABLE chrome_extension_observations DROP COLUMN may_disable;
ALTER TABLE chrome_extension_observations DROP COLUMN may_enable;
