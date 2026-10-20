# Email removal and follow-up audit — 20 October 2026

ExtSecure 0.8.39 removes email delivery at the project owner's request. Administrator account authentication and 2FA are unchanged.

## Removed

- SMTP, Gmail OAuth and the unfinished Brevo transport and setup tools.
- Email-specific credentials and recipient configuration from local project settings.
- Monthly report send API, role grants, extension worker permission and send controls in both interfaces.
- Email-only report delivery columns (`sent_at`, `delivery_outcomes`) and historical email notification events through migration 0012.
- Email-specific tests and obsolete setup guides; retirement regression tests now prevent email delivery from reappearing accidentally.

## Preserved

In-extension alerts, High/Critical threat blocking, incident cases, accounts, device/extension controls, security events, user feedback/suggestions and optional signed HTTPS webhooks remain. Weekly/monthly AI report schedules, report generation, aggregate statistics, ML analysis and saved report history remain. Reports are reviewed in the extension; they are not emailed.

## Live database verification

A private PostgreSQL backup was created before migration. Migration 0012 was applied successfully. Every retained record was compared before and after cleanup; report body, subject, statistics and generation metadata were preserved. One saved monthly report remains. There were no email notification events to delete. The two delivery-only columns are absent. Database health is successful across 40 tables and 8 views. No other project tables were dropped.

Private backup and verification artifacts stay outside GitHub. Historical audit documents are marked as historical where they describe the retired email feature.

## Problems found and addressed

- Removed stale report send actions, worker grants, backend imports and runner logic so older controls cannot trigger a partially removed feature.
- Added an upgrade check for older PostgreSQL installations and a tested SQLite upgrade that preserves report content while removing legacy delivery columns.
- Corrected report-history columns that incorrectly displayed device access and heartbeat fields. Device inventory retains those columns.
- Added missing legacy dashboard navigation entries directing users to the existing Chrome feedback/suggestion tools, matching backend role profiles.
- Installed the already-declared `tldextract` dependency missing from the development Python environment; the optional combined API test now passes.
- Recovered the offline local AI runtime. The supervisor confirms local API, public HTTPS and local AI are available. No cloud-model fallback was enabled.
- Updated stale database test assumptions to follow the actual migration sequence and verify transactional rollback against the next unused revision.

## Verification

- Broad backend suite: 656 passed, 17 environment-dependent skips and 16 passing subtests.
- Targeted report, ML, scheduling and webhook suite: 57 passed.
- Retirement/storage/runner/dashboard checks: 49 passed.
- Combined API and role-navigation retests: 10 passed after fixes; the other 86 checks in that host suite had already passed.
- Extension JavaScript suite: 257 passed, followed by a passing additional route-retirement regression.
- Real Chromium: 4 startup/worker/API/layout checks and 14 containment checks passed in isolated profiles.
- Live TestAPI health: HTTP 200 locally and over the current public HTTPS tunnel.
- Retired report send route: HTTP 404. Report generation remains in the running API schema.
- Local AI runtime: HTTP 200; supervisor reports ready.
- Dedicated PostgreSQL checks: all 17 checks passed across the initial run and targeted retests, including backup/restore, database constraints, runtime audit protections, transactional migration failure/rollback and email-only cleanup preservation. Test fixture issues were corrected without relaxing database constraints. Disposable test databases were removed.

The public extension ZIP and installed extension directory were updated. Existing unpacked Chrome installations need Reload; copies on other devices must receive the updated files. A temporary tunnel is not a permanent hosting address. These checks cover current known behavior and do not guarantee the absence of all future defects.
