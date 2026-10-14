-- migrate:up
CREATE INDEX IF NOT EXISTS ix_inventory_active_device ON inventory_browser_credentials (device_id) WHERE revoked IS FALSE;
-- migrate:down
DROP INDEX IF EXISTS ix_inventory_active_device;
