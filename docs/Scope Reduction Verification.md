# Scope reduction verification

Extension version: 0.8.13.

Removed 13 dedicated source, test, setup and documentation files; removed UI navigation, handlers, API grants, backend routes and scheduled workflow execution. General domain import and migration checksum comparison were removed. Basic migrations, safe export, backup recovery, detection evaluation and incident containment remain.

Migration 0004 was applied to the configured PostgreSQL database after a private backup. Six optional-feature tables were removed; scans, incidents, notes, threat blocks and audit tables were verified present. The updated TestAPI health succeeded; its live OpenAPI contains case and blocklist routes and zero workflow/control/policy/operations routes.

Validation:
- Extension suite: 209 passed.
- Focused backend scope/containment/governance/export suite: 69 passed.
- Full Python project suite: 718 passed, 3 navigation mismatches found, 16 environment-dependent tests skipped, 16 subtests passed. The navigation mismatches were fixed; all 49 dashboard regression tests then passed.
- Real PostgreSQL containment suite: 11 passed in an isolated disposable database.
- Real Chrome containment/UI checks: 9 passed with synthetic threat evidence in a separate browser profile.

Reload the installed Chrome extension to activate the new worker and UI. High/Critical hostname blocks and file-hash records remain; file hashes do not quarantine files in the operating system. Historical SQL migrations and administrative audit records are retained for upgrade and investigation integrity. Removed-feature data restoration requires the private database backup, not migration rollback.
