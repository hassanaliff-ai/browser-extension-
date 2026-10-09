-- migrate:up
CREATE INDEX IF NOT EXISTS ix_alerts_created_at ON alerts(created_at);
-- migrate:down
DROP INDEX IF EXISTS ix_alerts_created_at;
