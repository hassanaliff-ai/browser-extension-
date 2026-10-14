-- migrate:up
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='devices'::regclass AND conname='ck_devices_inventory_revision') THEN ALTER TABLE devices ADD CONSTRAINT ck_devices_inventory_revision CHECK (inventory_revision >= 1); END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='extensions'::regclass AND conname='ck_extensions_inventory_revision') THEN ALTER TABLE extensions ADD CONSTRAINT ck_extensions_inventory_revision CHECK (inventory_revision >= 1); END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='device_registrations'::regclass AND conname='ck_device_registrations_revision') THEN ALTER TABLE device_registrations ADD CONSTRAINT ck_device_registrations_revision CHECK (revision >= 1); END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='inventory_device_enrollments'::regclass AND conname='ck_device_enrollment_status') THEN ALTER TABLE inventory_device_enrollments ADD CONSTRAINT ck_device_enrollment_status CHECK (status IN ('pending','approved','blocked','rejected')); END IF; END $$;
-- migrate:down
ALTER TABLE inventory_device_enrollments DROP CONSTRAINT IF EXISTS ck_device_enrollment_status;
ALTER TABLE device_registrations DROP CONSTRAINT IF EXISTS ck_device_registrations_revision;
ALTER TABLE extensions DROP CONSTRAINT IF EXISTS ck_extensions_inventory_revision;
ALTER TABLE devices DROP CONSTRAINT IF EXISTS ck_devices_inventory_revision;
