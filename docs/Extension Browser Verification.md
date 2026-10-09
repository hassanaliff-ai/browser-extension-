# Real extension and database verification

Verified on **9 October 2026** with ExtSecure **0.8.11**, the running TestAPI,
PostgreSQL 18, and Playwright Chromium/Chrome for Testing in a separate profile.

## Testing setup repaired

The desktop-control tool could not reliably identify the current extension URL
and therefore stopped. This was a tooling limitation, not a reported ExtSecure
exception. The new browser smoke runner uses the supported Playwright extension
workflow to load the real MV3 package, worker and Chrome APIs in a dedicated test
profile. It does not attach to the personal Chrome session, modify desktop-tool
policy, bypass authentication, or replace the extension with a website preview.

The reusable runner is `extension/tests/browser-smoke.mjs`; the masked-entry
launcher and private database comparison are `scripts/test_extension_browser.py`.
Setup and commands are in [the extension README](../extension/README.md).

## Verified checks

- **215 extension tests passed**, covering worker transport, inventory, access
  approvals, local hashing, roles, reports, workflow actions, preferences,
  navigation, table sizes and UI handlers.
- **156 backend integration tests passed**, covering authentication, role access,
  scan attribution, file reputation/cache, device enrollment, website approvals,
  workflow automation, and reporting/notification behavior in isolated test data.
- The first live browser run passed 20 checks. A repeat run passed **21 checks**,
  adding a check that real blocked navigation is persisted for control metrics.
- The anonymous masked-entry launcher also passed all four startup checks.

Live checks exercised the real service worker and TestAPI: initial signed-out
state, desktop sign-in layout, password challenge, authenticator verification,
24-hour session expiry, current-profile device registration, URL lookup,
local-file hashing, seven console views (history, events, devices, extensions,
workflow, controls and reports), DNR website blocking, navigation evidence,
table-size persistence after reload, JavaScript error checks and sign-out.
The final live run had no uncaught console-page JavaScript errors. Both test
sessions were revoked afterward; other sessions were retained.

## Actual database changes

Across the two live runs, all **42 tables** were compared by primary-key and
per-column hashes. Total rows increased from **132 to 164**, including the two
unchanged migration-ledger rows. The existing health CLI counts application rows
separately from the ledger. There were **32 additions, no removals**, changes in
17 tables and no changes in the other 25. No schema changes were made by these
browser tests; all eight reporting views and integrity checks remained healthy.

| Table | Before | After | Added | Existing rows updated |
| --- | ---: | ---: | ---: | ---: |
| admin_auth_state | 2 | 2 | 0 | 1 |
| admin_login_challenges | 22 | 24 | 2 | 0 |
| admin_sessions | 18 | 20 | 2 | 0 |
| devices | 1 | 2 | 1 | 0 |
| domains | 0 | 1 | 1 | 0 |
| file_reputation_cache | 1 | 2 | 1 | 0 |
| governance_audit | 57 | 64 | 7 | 0 |
| security_navigation_evidence | 3 | 4 | 1 | 0 |
| virustotal_quota | 1 | 1 | 0 | 1 |
| device_registrations | 1 | 2 | 1 | 0 |
| extensions | 2 | 3 | 1 | 0 |
| inventory_browser_credentials | 1 | 2 | 1 | 0 |
| inventory_device_enrollments | 1 | 2 | 1 | 0 |
| chrome_extension_observations | 2 | 3 | 1 | 0 |
| scans | 2 | 6 | 4 | 0 |
| personal_scan_ownership | 2 | 6 | 4 | 0 |
| security_events | 2 | 6 | 4 | 0 |

The updated existing records were the head account's TOTP replay counter and the
VirusTotal quota-window timestamps. Accounts, role assignments, policies,
whitelist entries and existing audit history were not changed. The additional
device is clearly named **ExtSecure QA browser 2026-10-09**; its inventory and
connection records are retained so this test can be distinguished from an
ordinary user's workstation. New challenge/session records are consumed/revoked
test history, not additional active sign-ins.

## Scan evidence

| Test | New records | Observed result |
| --- | ---: | --- |
| example.com URL | 2 | Low, score 0, complete assessment |
| Generated harmless text-file hash | 2 | Unknown, no score, unavailable reputation evidence |

The real file-result UI reported that VirusTotal had **no report for this hash**.
The lookup ran; Unknown is the correct lack-of-evidence result and is not a clean
verdict. File contents remained in the browser; only SHA-256 was submitted. The
URL's test query parameter and fragment were removed before lookup/storage.

Read-only SQL verification confirmed all four new scans have matching personal
ownership, device, extension and security-event attribution. A real blocked
navigation record and corresponding audit entry were also stored. These benign
checks produced no confirmed threat findings or high-severity alert records.
Threat notifications and incident behavior were covered by the isolated backend
tests; this live check did not deliberately trigger real email/webhook delivery
or LLM report generation. Loading a Reports view is not a delivery test.

The API runtime role remains unable to update/delete audit history or create
tables. Credentials, live record contents, browser profiles, raw snapshots and
screenshots are private and excluded from GitHub; this document contains only
aggregate verification and deliberately chosen test inputs.

Reference: [Playwright Chrome-extension testing](https://playwright.dev/docs/chrome-extensions).
