-- migrate:up
ALTER TABLE devices ADD COLUMN IF NOT EXISTS inventory_removed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS inventory_revision INTEGER NOT NULL DEFAULT 1;
ALTER TABLE extensions ADD COLUMN IF NOT EXISTS inventory_removed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE extensions ADD COLUMN IF NOT EXISTS inventory_revision INTEGER NOT NULL DEFAULT 1;
-- migrate:down
ALTER TABLE extensions DROP COLUMN inventory_revision;
ALTER TABLE extensions DROP COLUMN inventory_removed;
ALTER TABLE devices DROP COLUMN inventory_revision;
ALTER TABLE devices DROP COLUMN inventory_removed;
