# User feedback verification — 18 October 2026

Extension version: **0.8.30**. Database migration: **0010**.

## Results

| Check | Result |
| --- | --- |
| Feedback, role and governance backend regression run | 59 passed |
| Final focused feedback run after UTC and list-query adjustments | 16 passed |
| Feedback and relational integration on disposable PostgreSQL | 27 tests, successful exit |
| Extension JavaScript suite | 243 passed |
| Real MV3 Chrome feedback workflow | 8 checks passed |
| Live local API feedback routes and authentication | Verified |
| Live PostgreSQL schema and migration ledger | Healthy; 0010 applied |

The runs overlap; these figures must not be added together as a unique test total.

## Chrome workflow

1. A normal user signed in with password and authenticator and submitted a
   warning challenge from a linked scan.
2. Feedback containing HTML was displayed as plain text.
3. The administrator opened the original evidence from the feedback workspace.
4. The administrator saved an outcome and review explanation.
5. The original Critical severity and active threat block remained unchanged.
6. The feedback workspace fit a 390-pixel viewport.
7. The user signed in again and saw the saved administrator decision.
8. No page JavaScript errors occurred.

Browser tests used generated accounts and synthetic evidence in an isolated
database and Chrome profile. They did not contact a reputation service or send
external notifications. Authenticator replay protection remained enabled.

## Deployment

A private PostgreSQL backup was created before the additive migration. Live
schema checks passed and existing scan evidence remained present: 16 scans,
0 alerts and 1 incident case at verification. The new feedback table was empty
because no real user had submitted feedback yet; synthetic tests were isolated.

The local API exposed the new endpoints and rejected unauthenticated access.
The installed unpacked extension files were updated. Chrome must reload the
extension to activate the updated service worker. Private backups, generated
credentials, browser profiles and test databases are excluded from GitHub and
the installation ZIP.
