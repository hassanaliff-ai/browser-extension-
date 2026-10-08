# Workflow activation verification — 8 October 2026

Extension 0.8.10; monitoring API 0.4.1 unchanged.

## Diagnosis

Read-only aggregate inspection of the local deployment found no workflow rules, no incident cases and no workflow notices. Its two scans were Low and Unknown. The public capability endpoint reported that the monitoring service and workflow runner were available. Without an enabled matching rule, assignment, review notifications and escalation have nothing to process. No backend execution defect was reproduced in the workflow tests.

## Applied configuration

At the project owner's request, one enabled rule was configured for new High/Critical website and file results. The configured head administrator is the investigator, reviewer and escalation recipient; the deadline is 24 hours. It excludes Unknown results and applied exceptions through the existing matching logic. The configuration was backed up locally and recorded in the governance audit as a system maintenance action with its reason. Repeating setup preserved the existing rule without creating another rule. Private configuration and database backups are excluded from GitHub.

There are still no live incidents or notices because no matching new threat has been recorded. Historical Low/Unknown records were not changed into synthetic threats. A 24-hour escalation to the same head administrator creates an escalation notice while keeping that investigator.

## Console changes

- Visible workflow status uses the protected API's actual runner state and active rule recipients.
- Missing/disabled rules, unavailable recipients, starting/stopped/failed checks, and manual-case-only rules receive specific explanations.
- Enabled rules, automatic case rules and unread notification counts are shown.
- Notification actions display human-readable labels; an explicit refresh retrieves current notices.
- Empty inbox text explains what will produce notifications. Detailed workflow rules are in a disclosure panel.
- New console messages support English and Arabic. Existing permissions and security behavior remain intact.

## Verification

- **31 backend tests passed**, including a new authenticated sequence: create a head-admin rule, ingest an isolated threat, verify assignment and review notices, acknowledge both, verify the incident remains open, advance the test clock beyond 24 hours, verify one escalation notice and no duplicate escalation.
- **214 extension tests passed**, including readiness checks for empty/disabled rules, valid rules, revoked investigators/reviewers, invalid escalation roles, mixed rule sets, manual-only rules and stopped/failed runners.
- Isolated Chrome tests passed for rule creation, acknowledgement, case navigation, control assessment submission, reporting periods and manager scoping.
- Eight language/theme/layout checks passed, along with missing-configuration/ready states, notification refresh and two legacy-worker recovery checks.
- Production scans, cases and accounts were not replaced by test records. Deadline verification used isolated data and a simulated test clock, not a 24-hour production wait.

## Use

Refresh Workflow automation to see the configured rule. Reload ExtSecure on `chrome://extensions` and reopen the console to load the latest readiness UI. Live activation in the user's existing Chrome session was not directly verified because this session had no Chrome control surface. New qualifying scans create incidents and notices; unresolved linked incidents escalate when their deadline is reached. The API must remain running for scheduled checks.
