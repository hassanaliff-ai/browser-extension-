-- migrate:up
ALTER TABLE file_reputation_cache ADD COLUMN IF NOT EXISTS provider_evidence JSON;
-- migrate:down
ALTER TABLE file_reputation_cache DROP COLUMN IF EXISTS provider_evidence;
