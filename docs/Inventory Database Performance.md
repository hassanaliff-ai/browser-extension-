# Inventory database performance

ExtSecure 0.8.26 keeps the existing feature scope and improves the device and extension inventory reads. Device metadata is fetched in three related-data queries, independent of the number of devices. Extension names, registrations, observations and controls are fetched in batches instead of separate queries for every row. Existing status, revision, removal and protection fields remain unchanged.

Migration 0008 adds a partial index for active browser credentials, matching the existing device-link query. It does not add tables, remove rows or rewrite security evidence. The database health check verifies that this index exists. Existing integrity checks, access controls, transaction locks, history and retained real-test results remain in place.

Validation passed: 59 backend regression checks, 21 checks in the isolated database run (13 against PostgreSQL and eight SQLite role checks), and 232 extension tests. A 40-device fixture verified that related device metadata uses exactly three queries. Metadata comparisons confirmed the same output as the individual-record implementation, and PostgreSQL migration replay and rollback were verified.

Chrome's current unpacked extension folder is `SecureScope Integrated/extension` in the user's Alba Project workspace. That folder receives the same version update as the primary repository. Reloading the running Chrome extension is required to activate changed worker files; replacing files alone does not confirm the running version.
