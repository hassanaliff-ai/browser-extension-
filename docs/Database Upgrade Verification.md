# PostgreSQL upgrade verification

Verified on **9 October 2026**. Expected schema revision: `2026-10-09.2`.

## Delivered changes

| Requirement | Implementation |
|---|---|
| Database design | 41 application tables, named integrity constraints, targeted history indexes and reproducible SQL export |
| Persist security evidence | Existing scans, domains, findings, risk results, alerts, events and audit storage retained; two new evidence/domain reporting views |
| Relationships and transactions | Composite device/extension attribution checks, validated additive upgrades, transactional domain upserts and verified record preservation |
| Extension/dashboard/report queries | Bound device/time filters, cursor history, domain risk ranking, independently aggregated report totals and eight PostgreSQL views |

Risk remains a canonical assessment on its scan, exposed through a view rather
than duplicated into a second mutable record. Unknown results remain visible
separately from Low risk. The new queries are reusable backend helpers; extension
routes and the account privilege hierarchy remain compatible.

## Tests

**11 real PostgreSQL integration tests passed.** They cover:

1. Foreign-key and risk-field validation.
2. Concurrent domain upserts and stable first/last-seen times.
3. Scan history, stored policy version and UTC reporting views.
4. Domain/scan/device transaction rollback.
5. Verified SQLite import with authenticated API compatibility.
6. Complete rollback when migration row digests do not match.
7. Runtime startup, audit append-only permissions and schema-write rejection.
8. Device/extension attribution, child validation and domain time ordering.
9. Idempotent owner upgrade with preservation of existing rows.
10. Rejection of conflicting legacy attribution without rewriting evidence.
11. Independent finding/alert/event counts in the evidence view.

**94 API/query/schema/governance/reporting compatibility tests passed.** These
include equal-timestamp cursor pagination, device scope, insertion between pages,
empty report windows, child-row double-count prevention and parameter binding.

The generated `sql/schema.sql` also executed successfully in a separate empty
PostgreSQL test database. Inspection confirmed all 41 tables, eight views and
required named constraints/indexes. Disposable test databases were removed after
verification; no test fixtures were inserted into the live database.

## Live upgrade

- Created a private custom-format PostgreSQL backup before applying changes.
- Verified counts and canonical SHA-256 row digests for all 41 existing tables.
- Preserved 125 existing records; no data cleanup or rewriting was required.
- Read-only health inspection passed with all expected schema objects present.
- Device and extension attribution checks reported zero conflicts.
- Runtime `extsecure_app` cannot create tables or update/delete governance audit records.
- API health returned HTTP 200; workflow runner ready; unauthenticated scan listing returned HTTP 401.
- Existing `.env` and account/authentication settings remained unchanged.

The private backup and verification files stay under `.private/updates/` and
are excluded from GitHub. A backup is available for controlled recovery; an
automatic dump restore is deliberately not performed during an upgrade failure.

## Practical limits

The live dataset is small. History indexes and bounded cursor queries are present,
but production-scale latency and load have not been benchmarked. SQL helpers are
trusted backend components: callers must still apply role/device authorization.
Database owner privileges allow maintenance, including audit modification;
append-only restrictions apply to the API runtime role. Existing legacy SQLite
tables are not rebuilt to retrofit every PostgreSQL constraint.

See [database setup and operational commands](PostgreSQL%20Database.md).
