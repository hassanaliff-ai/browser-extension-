# Existing feature integrity

Version 0.8.23 strengthens existing database and extension behavior without introducing new project responsibilities or features.

PostgreSQL now checks that device, extension and registration revisions are positive and that enrollment states are valid. Migration 0007 adds these checks without deleting or rewriting evidence. The structural health check verifies the additional constraints.

Inventory writes lock their device before applying a snapshot. Concurrent snapshots for the same device are serialized, avoiding duplicate extension inserts and conflicting snapshots. Connection retries, pairing and scan recording recheck current device state. Removal, access decisions and pairing-code changes share the same device lock so stale reads cannot reopen removed inventory. These locks are held only for the transaction and do not lock other devices.

Chrome clears temporary navigation grants when the API rejects a removed or inactive device connection. Persistent threat blocks remain in place, and account sign-in is preserved for recovery. No automatic retry is added to write requests.

Regression tests cover invalid database writes, stale device snapshots, real concurrent PostgreSQL inventory writes, administrator permissions, migration replay and rollback, and the existing Chrome management controls. Tests use disposable fixtures rather than adding sample records to the live database.

Verification: the backend regression run passed 52 tests; the final inventory run passed 40. Each SQLite run skipped the PostgreSQL-only concurrency test, which passed in the isolated PostgreSQL run. That run passed 19 checks (11 against PostgreSQL and eight SQLite role checks). All 232 extension tests and 19 real Chromium checks passed. Live migration 0007 preserved all 274 existing records, and the running API and PostgreSQL health checks passed. A private backup was created before upgrading.
