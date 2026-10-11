# PostgreSQL connection and persistence

The deployed project is `C:\Users\hassa\browser-extension-`. TestAPI uses PostgreSQL at `127.0.0.1:5432`, database `extsecure`, schema `public`, with the restricted `extsecure_app` role. Chrome connects to TestAPI at `http://127.0.0.1:8765`; it never connects directly to PostgreSQL or receives database passwords.

The database contains the full current application schema: devices and Chrome inventory, domains, scans and risk evidence, findings, alerts, security events, accounts and authenticator sessions, access decisions and whitelist entries, incidents and notes, append-only administrator audit, privacy settings, evaluations, reputation cache, and weekly/monthly AI reports. Eight SQL views support evidence, history, domain risk and reporting. The schema has 36 application tables plus the migration ledger. Removed optional features have not been restored.

## What was corrected

The API was not running when this verification began. Starting the installed project's `Start ExtSecure.cmd` restored the live connection. Scans and personal-history ownership previously used separate commits. Ownership now commits in the same transaction as the scan, findings, security events, alerts and containment. A failed write rolls back the transaction and returns HTTP 503 rather than silently leaving a partial history. Cached and Unknown reputation results are still saved as new scan evidence.

Administrators can now open **Settings → Database connection** in the extension console. `GET /monitor/api/database/status` verifies the runtime connection, current database/schema, required tables, constraints, indexes, views, record counts and evidence attribution. The read-only snapshot is consistent across its queries and contains no passwords, connection strings, record contents or account secrets. Managers and normal users cannot call this diagnostic endpoint. A non-PostgreSQL test deployment is clearly identified rather than presented as verified PostgreSQL storage.

## Find the records in pgAdmin

Open the local PostgreSQL server, then **Databases → extsecure → Schemas → public → Tables**. Selecting the maintenance database `postgres` or another database will not show ExtSecure's tables. For risk results, history and aggregates, open **Views**. Run `sql/verify_connection.sql` in the `extsecure` Query Tool to verify the connection and recent evidence without modifying data. `sql/schema.sql` contains the complete generated table/index/view definitions; it is intended for a new empty database, not reexecution over existing tables.

The API writes scan evidence transactionally to `scans`, `personal_scan_ownership` and `security_events`; detected signals additionally create `findings`, and High/Critical risks create `alerts` and containment evidence. Empty findings/alerts tables are expected when scans have no confirmed threat. Reports and other workflow tables receive records when their actual workflows run. Production tables are not padded with synthetic malicious findings.

## Live verification

An approved account completed password and authenticator verification. An isolated real Chrome profile enrolled through the real inventory API, checked `https://example.org/`, and submitted only the SHA-256 of a harmless local test string. No API fetches or reputation responses were mocked in this browser verification. The website received Low risk; the unrecognized file hash received Unknown. Both results appeared in personal history, with events attributed to the enrolled Chrome device and approved account.

Across the verification runs, live scans, security events and personal ownership rows increased from 7 to 11. Devices increased from 2 to 3, extensions from 3 to 4, and domains from 2 to 3. Existing records were preserved. The additional device is explicitly named `Chrome database integration verification`. Its temporary administrator session was logged out after testing; private credentials and sessions are excluded from Git.

Automated PostgreSQL tests use disposable `extsecure_test_*` databases, and validate relational constraints, rollback, migrations, reporting views, restricted runtime permissions, incident containment and ownership atomicity. They never reset or insert synthetic threats into the live `extsecure` database.

Final checks: 118 backend tests, 38 isolated real PostgreSQL tests, 216 extension unit tests, and 8 live Chrome-to-TestAPI-to-PostgreSQL checks passed. Read-only verification found no missing required tables, views, constraints or indexes, and no mismatched scan/device/extension relationships.
