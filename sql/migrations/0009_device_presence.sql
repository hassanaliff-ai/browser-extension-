-- migrate:up
ALTER TABLE device_registrations ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMP WITH TIME ZONE;
-- migrate:down
ALTER TABLE device_registrations DROP COLUMN IF EXISTS last_heartbeat;
