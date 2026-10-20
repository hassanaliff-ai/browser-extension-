-- migrate:up
ALTER TABLE monthly_reports DROP CONSTRAINT IF EXISTS ck_monthly_report_status;
UPDATE monthly_reports SET status='draft' WHERE status <> 'draft';
ALTER TABLE monthly_reports DROP COLUMN IF EXISTS sent_at;
ALTER TABLE monthly_reports DROP COLUMN IF EXISTS delivery_outcomes;
ALTER TABLE monthly_reports ADD CONSTRAINT ck_monthly_report_status CHECK (status IN ('draft'));
DELETE FROM security_events WHERE event_type='notification_delivery' AND details->>'channel'='email';
-- migrate:down
-- Email delivery was deliberately retired. Restore private backups to recover its metadata.
SELECT 1;
