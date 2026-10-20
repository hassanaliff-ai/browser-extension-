# Hasan role audit — 20 October 2026

Release: ExtSecure 0.8.38. Scope was taken from Project Scope.md and the owner's current role requests. Removed advanced monitoring, policy approval, assignment/escalation automation, general importing and control-effectiveness features were not restored. VirusTotal/RDAP module ownership and unrelated proposal/reflection files were left outside the changes.

## Findings fixed

1. Account disable requests previously accepted no confirmation or reason at the backend. A strict confirmation and meaningful reason are now mandatory. The audit records the reason, existing sessions are revoked and the owner remains protected.
2. The account-management form could retain a confirmation made for a different person or action. Changing the account, role or action now clears the old reason and confirmation. The UI explicitly explains that disabling prevents future login.
3. Chrome approval-cleanup failure could prevent persistent threat-rule installation. The persistent high-priority block is now installed first; a cleanup failure leaves protection active and shows recovery guidance.
4. A disappearing/unavailable tab could stop redirecting subsequent dangerous tabs. Processing now continues and reports partial redirect failure. Tab-query failures also leave the persistent block active.
5. File containment could interpret an accidentally supplied filename as a URL. Only URL scans create hostname rules; file checks remain hash containment and do not claim OS quarantine.
6. The local Ollama service was stopped despite local AI being configured. Its existing hidden loopback-only runtime has been recovered, and the existing API supervisor now also checks/restarts local AI without cloud fallback.
7. Scheduled report startup unnecessarily depended on the public API/tunnel. The scheduler now checks its local model directly and reads PostgreSQL independently. The missed weekly report for the period starting 11 October 2026 was generated and retained for review.
8. One reporting regression test cleared only the cloud model variable. It now isolates both cloud and local provider settings and verifies missing-model rejection for each provider.
9. The account-role guide contained outdated approval and removed-feature descriptions. It now matches the current pyramid, permanent account validity, 24-hour sessions and supported scope.

## Role coverage

| Retained responsibility | Audit evidence |
| --- | --- |
| PostgreSQL design, storage, integrity, queries and safe export | Live read-only schema/attribution inspection; isolated PostgreSQL integration tests; database/query regressions. |
| Backup and recovery | A fresh private backup restored successfully into a disposable database: 40 tables and 526 snapshot rows, matching schema/row/view digests. Production was not restored over. |
| Risk scores, severity, UI and administrator dashboard | Broad risk/API regression, extension tests, strict Unknown handling, current role checks and real Chrome exercises. |
| Security-event and audit logging | Relationship checks returned zero scan/device/extension mismatches; runtime role cannot UPDATE/DELETE audit records or CREATE tables. |
| Accounts, approval and 2FA | Registration, repeated login, explicit disabling, role enforcement and original account/session separation tested. No live account was disabled/deleted or assigned a new role by this audit. |
| Whitelist, overrides and website access | Broad tests cover approval durations, confirmations, ownership and containment precedence. |
| Downloaded-file hash checks | File-lookup boundary tests, hashing tests and improved file-containment handling. Native filesystem quarantine is not implemented. |
| Weekly/monthly AI reporting and ML | Local provider recovery, schedule idempotency, period bounds, report validation and ML regressions. A real synthetic local-model summary passed; the missed real weekly report was saved. |
| High-severity alerts | Email/webhook adapter tests pass. Administrator supplied an email recipient and selected ExtSecure as sender display name; Gmail SMTP settings are private. Live email authentication/delivery remains pending local app-password setup. |
| Privacy/data governance | Ownership, consent, retention holds, safe export and role tests. Private backups, settings, browser profiles and credentials are excluded from Git. |
| Incident response and cases | Incident safety/removal, blocking, stale revisions and preservation of threat blocks tested. |
| Detection quality, guidance and usability/accessibility | Automated evaluation, evidence/uncertainty labels, language/RTL and UI regression checks. No claim of human usability-study or screen-reader certification is made. |
| User feedback and suggestions | Ownership/reviewer controls and PostgreSQL integration checks. |

## Results and limits

- Broad initial backend audit: 651 passed, 17 environment-specific tests skipped, 16 subtests passed, one provider-configuration test failure. That failure was corrected and its affected suite passed afterward; the whole 12-minute run was not repeated.
- Final affected account/role/audit/incident/dashboard suite: 89 passed.
- Final local recovery/scheduler/supervisor suite: 29 passed.
- Final reporting/notification/local-model/supervisor suite: 62 passed.
- Extension JavaScript: 257 passed.
- Isolated real PostgreSQL integration: 41 passed, one environment-specific check skipped.
- Real Chrome account workflows: 14 checks passed using temporary accounts and database.
- Real Chrome containment/incident UI: 14 checks passed with synthetic evidence and real Chrome blocking rules.
- Actual public ZIP: five real Chrome connection/CSP/UI checks passed without using account credentials.
- Masked Gmail setup: six tests passed, including TLS/authentication, rejected credentials, input/header validation and no message sending.
- Live API and local AI health checks returned 200. The deployed API schema requires disable confirmation and reason, and anonymous disable probes returned 401.

Counts above overlap; they are not added into an invented unique-test total. Tests and review reduce specific risks and do not guarantee absence of every future defect. Live third-party notification delivery and human accessibility testing are not established by mocks or synthetic browser results.

## Deployment and remaining setup

The updated installed workspace extension and downloadable ZIP use TestAPI at:

https://joan-designated-explosion-result.trycloudflare.com

On another device, replace files in the same existing unpacked-extension directory and Reload at chrome://extensions. GitHub uploads do not automatically update unpacked installations. This is a temporary HTTPS tunnel and can change after recreation; a stable production API remains a separate deployment requirement.

The administrator email address, sender account and password are not included in this report or GitHub. The local setup tool scripts/configure_gmail_alerts.py masks the Gmail app password, verifies STARTTLS authentication, saves it only to private server settings and sends no email. TestAPI must reload settings after successful setup. Until sender authentication is configured, external email alerts are not ready, even though on-console alerts and blocking remain available.

Gmail setup references:

- https://support.google.com/mail/answer/185833
- https://developers.google.com/workspace/gmail/imap/imap-smtp
