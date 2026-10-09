# Database operations verification

Verified on **9 October 2026** using the installed ExtSecure project, local
PostgreSQL 18, and TestAPI at `http://127.0.0.1:8765`.

## Deployed changes

| Responsibility | Delivered behavior |
| --- | --- |
| Backup and recovery | Snapshot-consistent custom-format backups, SHA-256 manifests, and restores into disposable databases with table/schema/view verification. |
| Performance | Reproducible synthetic benchmarks, query plans and timing samples; an alert-period index included in schema and migration 0002. |
| Migrations | Numbered SQL files, checksummed application ledger, transactional execution, advisory locking, and test-only rollback. |
| Monitoring | Aggregate size/activity/capacity metrics, adjustable thresholds, growth and deadlock checks, and private diagnostic alerts. |
| Data exchange | Allowlisted JSON/CSV exports, privacy enforcement, validated domain imports, default dry runs, and audited atomic commits. |

The live upgrade backed up the database before modification. Row counts and
content hashes matched for all **41 existing application tables**. The database
now has **42 tables** including the migration ledger, and **8 reporting views**.
Migration versions **0001 and 0002** are recorded; the expected schema revision is
`2026-10-09.3`. The runtime role remains unable to modify audit history or create
tables. Existing private configuration was preserved.

## Automated checks

**66 tests passed** across two suites:

- **47 compatibility and validation tests:** operator input validation, duplicate
  merging, dry-run behavior, export bounds, privacy policy, path containment,
  monitoring thresholds, migration checksums, existing query/schema tests and
  PostgreSQL activation behavior.
- **19 real PostgreSQL tests:** the existing integration suite plus new snapshot
  backup/restore, tampered-backup rejection, migration idempotency, ledger grants,
  altered migration rejection, transactional rollback, test-only rollback,
  domain import, real monitoring and isolated benchmark checks.

PostgreSQL integration tests created and removed disposable databases. They did
not insert synthetic records into the live database.

## Live operations

- The maintenance CLI completed with healthy monitoring.
- The snapshot backup restored successfully: **42 tables and 132 rows**, matching
  the recorded schema/table hashes and all eight view shapes/results. The restore
  database was removed. This row total includes two migration ledger entries.
- Read-only scan-summary and domain exports completed into private files, with
  no truncation. The actual empty domain dataset was preserved; no observations
  were invented to fill it.
- A domain import dry run reported its proposed addition, then rolled back.
  Domain and audit counts were unchanged afterward.
- TestAPI health returned HTTP 200, the workflow runner remained active, and
  unauthenticated scan access returned HTTP 401.
- Windows Task Scheduler's **ExtSecure Database Maintenance** task was installed
  and run successfully with exit status **0**. Its trigger repeats every five
  minutes, uses the current user's interactive session and limited privileges,
  and schedules a backup every 24 hours and restore verification every seven days.
  The test run finished in the Ready state; no Windows password is saved.

## Performance sample

The isolated benchmark contained **10,000 synthetic scans**, 20 devices and
100 domains. Each main query used five `EXPLAIN ANALYZE` samples.

| Query | Median execution (ms) | Observed p95 (ms) |
| --- | ---: | ---: |
| Device history | 1.012 | 1.940 |
| Report totals | 9.973 | 10.477 |
| Domain rankings | 22.737 | 23.316 |

The selective alert-period count measured **0.348 ms before** the added index
and **0.088 ms afterward**. The resulting plan used `ix_alerts_created_at`.
These are local indicative measurements, not a concurrency or production SLA.
All benchmark data and plans stayed in private files; the temporary database was
removed.

## Boundaries

Backups, exports, credentials and live records are excluded from GitHub. The
tools provide local operator maintenance; they do not add extension privileges
or new public import/export endpoints. Restores verify trusted private dumps and
never overwrite the live database. Off-device backup replication and unattended
maintenance while logged out require a separately configured deployment.

Commands, configuration and recovery limitations are described in
[Database Operations](Database%20Operations.md).
