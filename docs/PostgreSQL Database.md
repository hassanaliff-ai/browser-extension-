# ExtSecure PostgreSQL database

The local deployment now uses PostgreSQL 18 on `127.0.0.1:5432`, database
`extsecure`. The API continues at `http://127.0.0.1:8765`; the extension's
authentication, approvals and API routes remain compatible.

## Data model and integrity

The live schema contains 41 tables, 89 indexes (including primary-key and unique
constraint indexes) and six reporting views. It stores
devices, scans, domains, findings, alerts, security events, incidents, approvals,
reports, account/session records and audit history. Risk results remain on the
scan record and are exposed through `extsecure_risk_results`, avoiding a second
independent copy of the score. Scans record the policy version used to assess them.

Foreign keys link scans to devices and domains and findings/alerts to their
scans. Checks reject invalid scores, severities, completeness states and target
types. A unique hostname constraint and transactional upserts prevent duplicate
domains during concurrent scans. Domain first/last-seen timestamps remain correct
when events arrive out of order. Scan recording and its related findings, alerts
and events use the existing shared transaction.

Domain tracking respects the hostname privacy setting. URLs are normalized;
embedded credentials, query strings and fragments are excluded from domain
records. Retention removes old orphaned domains without deleting domains still
referenced by retained scans.

## Queries

- [Schema](../sql/schema.sql): complete PostgreSQL DDL for a new empty schema.
- [Queries](../sql/queries.sql): parameterized scan history, findings, domain,
  alert, report and audit queries.
- [Python queries](../src/alba_security/database_queries.py): bounded history
  and aggregate queries, hostname normalization and transactional domain upserts.

Views: `extsecure_risk_results`, `extsecure_scan_history`,
`extsecure_alert_history`, `extsecure_daily_statistics`,
`extsecure_weekly_statistics`, `extsecure_monthly_statistics`.
Periods use UTC and half-open ranges. Aggregates count scans independently of
findings and alerts, preventing duplicate counts. Unknown results remain distinct
from high-risk detections. Account authorization still applies through the API;
these SQL views are for trusted backend use, not direct extension access.

## Local Windows setup

Install dependencies from `requirements.txt` using the project's Python environment.
Run from the project root:

```powershell
& .\scripts\enter_postgresql_credentials.ps1
$env:PYTHONPATH = "$PWD\src"
python .\scripts\setup_postgresql.py
python .\scripts\activate_postgresql.py
```

The first script prompts for the existing administrator password with masked
entry. It does not reset the PostgreSQL password or change authentication rules.
Encrypted credentials and generated role passwords are stored under `.private`
using Windows DPAPI, tied to this Windows account. Keep these files and `.env`
out of Git. `.env` contains the private runtime connection string.

Setup creates a dedicated owner `extsecure_owner` and runtime `extsecure_app`.
Neither is a superuser nor can create databases or roles. The runtime can read
reporting views and perform application DML, but cannot create tables.
`governance_audit` and `admin_override_audit` permit runtime reads and inserts;
updates, deletes and truncation are denied. This protects audit rows from runtime
modification; the database owner still has maintenance authority.

Activation supports this local Windows deployment and its existing file-backed
SQLite database. It stops only a recognized Uvicorn API on port 8765, takes a
SQLite backup, and imports into an empty PostgreSQL destination in one transaction.
Every table's count and canonical row digest must match before commit. Existing
accounts, sessions and encrypted authenticator records are preserved. A populated
destination is rejected rather than overwritten. Re-running activation after a
successful switch does not import again.

Backups and verification are under `.private/updates/postgresql-*` and
`.private/postgresql-migration-verification.json`. The original SQLite database is
retained. If activation/startup fails, the script restores the previous `.env` and
attempts to restart SQLite. A committed PostgreSQL import may remain for inspection;
do not retry an import into it or delete it without checking the failure.
After successful activation, SQLite is a historical backup, not a live replica.
Switching back later requires reconciling any new PostgreSQL records first.

## Verification

Real PostgreSQL integration: **7 passed**, covering foreign keys/check constraints,
concurrent domain inserts, reporting boundaries, transaction rollback, full
SQLite migration plus authenticated API access, forced digest-mismatch rollback,
and restricted runtime/audit permissions. Test runs used disposable
`extsecure_test_*` databases, removed afterward. SQLite compatibility suites also
passed (99 tests; a subsequent focused API/governance/query run passed 55).
The live migration verified all 41 tables and confirmed a PostgreSQL connection
from `ExtSecure API` using `extsecure_app`, API health, workflow readiness and
unauthenticated request rejection. Private records and credentials were not published.

Reference documentation: [PostgreSQL role permissions](https://www.postgresql.org/docs/18/sql-createrole.html)
and [SQLAlchemy PostgreSQL dialect](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html).
