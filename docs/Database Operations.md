# ExtSecure database operations

These tools implement the five additional SQL responsibilities. They run locally
under the Windows account that owns the encrypted PostgreSQL setup files; they
are not extension endpoints and do not expose database credentials to Chrome.
TestAPI remains at `http://127.0.0.1:8765`.

## Commands

Run from the installed project using the existing Python environment:

```powershell
python scripts/database_ops.py backup --verify-restore
python scripts/database_ops.py migrate
python scripts/database_ops.py monitor
python scripts/database_ops.py benchmark --rows 10000
python scripts/database_ops.py maintain
```

Results and configuration stay under `.private/database-operations/`; backups stay
under `.private/backups/`. None is committed to Git. Scheduled work uses the same
CLI and encrypted connection files. `scripts/check_database.py` additionally
reports structural checks and applied migration versions.

## 5 — Automated backup and recovery testing

`backup` uses `pg_dump` custom format with an exported repeatable-read snapshot.
The dump, table row counts/hashes, view result hashes and schema shape therefore
refer to the same state even while TestAPI writes new records. A completed backup
has a SHA-256 checksum and manifest; a partial backup is not marked successful.

`restore-test` checks the file checksum before creating a uniquely named
`extsecure_test_restore_*` database. `pg_restore` runs with the restricted owner
role, within one transaction, without restoring roles or grants. It compares all
table hashes, primary-key/column/constraint/index shape, and view columns/results
with the manifest. The temporary database is removed afterward. Production is
never overwritten by this tool. A valid view can have different deparsed SQL after
restore, so raw view SQL strings are not used as identity fingerprints.

Backups contain private application records, including authentication records.
Keep the private directories local and protected. Only this tool's trusted local
backups are accepted; do not place downloaded/untrusted dumps in that directory.
The checksum detects corruption, not a malicious person who can modify both the
dump and its manifest. Restore tests verify data/schema, not restored production
account grants. Controlled disaster recovery must also reapply runtime grants and
preserve the Windows-encrypted role configuration. No backups are automatically
deleted, and this local scheme is not an off-device disaster-recovery solution.

## 6 — Performance testing and optimization

`benchmark` creates an isolated `extsecure_test_benchmark_*` database containing
1,000–100,000 synthetic scans, 20 synthetic devices and 100 example domains.
It measures device history, report totals and domain rankings using five
`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` samples per query. Results include median,
observed p95 and query plans. It also measures a selective alert-period query
before and after `ix_alerts_created_at`, an index useful when reports do not filter
by alert status. The index is part of the application schema and migration 0002.

These are local indicative measurements, not a production load/SLA guarantee.
Synthetic records are never inserted into the real ExtSecure database. The
benchmark database is removed after the run. Testing never executes caller-supplied
SQL; measured statements are fixed read queries.

## 7 — Version-controlled migrations

The numbered files in `sql/migrations/` include explicit up/down sections.
`0001` records the already-provisioned baseline; `0002` adds the alert-period index.
The owner records each version, normalized-source checksum and application time
in `extsecure_schema_migrations`. A previously applied file cannot be edited
silently. Migrations run under an advisory lock in one transaction; failed DDL
and ledger changes roll back together. The API role can read the ledger but cannot
insert, edit or delete its history. Add future changes as new numbered files.

The database now has **41 application tables plus one migration ledger**.
`scripts/upgrade_postgresql.py` takes a private backup, preserves existing
application row hashes, applies the schema and numbered migrations, and restarts
TestAPI. The existing additive schema compatibility mechanism remains in place;
the ledger tracks the explicit operations migrations rather than retroactively
claiming a complete history of every earlier prototype change.

Rollback execution is restricted to `extsecure_test_*` databases. Production
recovery requires an inspected backup and compatible application version; the
tool will not blindly run destructive down migrations on live data.

## 8 — Monitoring and capacity planning

`monitor` reads numeric aggregates for ExtSecure: database size, connection
utilization, blocked sessions, long-running queries/transactions and deadlocks.
It uses the existing local PostgreSQL administrator for visibility into activity;
no additional account privileges or PostgreSQL authentication changes are granted.
It does not collect SQL text, passwords, account names or query parameter values.

Default thresholds are 1 GiB database size, 80% of the server connection capacity,
queries over five seconds, transactions over 60 seconds, any blocked session,
and growth over 100 MiB/day. These are adjustable development thresholds, not
universal production recommendations. Connection utilization uses cluster-wide
client connection count but does not expose other database names. Growth and
new-deadlock alerts need a prior snapshot; a first sample does not fabricate them.
Failure is recorded as failure, not a healthy result.

Edit `.private/database-operations/config.json` to adjust validated numeric limits
or the backup/restore intervals. `monitor.json` stores the latest sample;
`alerts.jsonl` stores threshold and maintenance failures locally. No email/webhook
destination is configured by this SQL task; these are operator diagnostic alerts.

## Scheduled operation

`maintain` acquires a database advisory lock, collects monitoring metrics, creates
a backup when 24 hours have elapsed, and tests recovery when seven days have
elapsed. State is saved atomically. A failed restore is retried on a later run
without falsely marking verification successful. Overlapping runs are skipped.

`scripts/install_database_schedule.ps1 -PythonPath <existing-project-python.exe>`
registers **ExtSecure Database Maintenance** in Windows Task Scheduler. It runs
every five minutes with limited privileges while this Windows user is logged in.
It uses no saved Windows password, does not elevate, and does not start TestAPI.
Sleeping/offline/logged-out machines cannot complete maintenance until available.
It refuses to replace an unrelated task using the same name. Disable this task
in Task Scheduler to stop recurring work.

## 9 — Controlled import and export

All files must be under `.private/database-operations/`. Examples:

```powershell
python scripts/database_ops.py export scan_summaries scans.json --start 2026-01-01T00:00:00Z --end 2027-01-01T00:00:00Z
python scripts/database_ops.py export domains domains.csv --start 2026-01-01T00:00:00Z --end 2027-01-01T00:00:00Z
python scripts/database_ops.py import-domains domains.csv
python scripts/database_ops.py import-domains domains.csv --commit
```

Exports use explicit allowlists. Scan summaries contain target kind, score,
severity, completeness, policy version and date; they exclude raw URLs, query
strings, device identifiers, accounts, passwords and tokens. Domain export uses
hostname and first/last-seen times and requires the hostname privacy policy to
permit collection. CSV formula prefixes are escaped. Exports are bounded to
5,000 records, report truncation and never overwrite an existing file.

Imports support domain observations only, using exactly `hostname`, `first_seen`
and `last_seen`. They cannot set risk results, account roles, device trust or
permissions. The full file is validated before writing: at most 2 MiB/5,000 rows,
canonical hostnames, aware ISO timestamps, valid time order and no extra fields.
Repeated hosts are merged and existing observations retain their earliest/latest
times. A dry run is the default; `--commit` applies all rows and an audit record in
one transaction. Privacy-disabled imports are rejected. File paths cannot escape
the private directory. Imports are local operator operations, not user uploads.

References: [PostgreSQL backups](https://www.postgresql.org/docs/18/app-pgdump.html),
[restore](https://www.postgresql.org/docs/18/app-pgrestore.html),
[EXPLAIN](https://www.postgresql.org/docs/18/using-explain.html),
[monitoring](https://www.postgresql.org/docs/18/monitoring.html),
[Windows task triggers](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger).
