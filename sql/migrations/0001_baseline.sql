-- migrate:up
DO $$ BEGIN
    IF to_regclass('public.scans') IS NULL OR to_regclass('public.domains') IS NULL
       OR to_regclass('public.extsecure_scan_evidence') IS NULL THEN
        RAISE EXCEPTION 'Provision the ExtSecure schema before recording the baseline';
    END IF;
END $$;
-- migrate:down
-- Baseline rollback never drops existing security evidence.
SELECT 1;
