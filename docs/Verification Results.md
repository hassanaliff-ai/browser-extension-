# ExtSecure — Full Task Test Report

**Test date:** 4 October 2026.
**Installed project:** `C:\Users\hassa\browser-extension-`.
**Scope:** Hasan's 14 technical responsibilities, monthly machine learning, account registration, role approval, and QR/manual authenticator enrollment.

The complete installed-project regression suite passed: **459 tests and 16
subtests, with zero failures, errors or skips, in 143.16 seconds**. An additional
**58 checks against the running installation passed**. The real VirusTotal
service also accepted an authenticated lookup for a public empty-file hash.
All **69 compared implementation, test and runtime-configuration files** match
the reviewed workspace source.

Several features have passing implementation tests but cannot complete their
real deployment workflow yet: LLM generation and email/webhook delivery lack
configuration, machine learning lacks historical activity, and independent
policy review needs a second approved administrator. Six earlier security
findings were reproduced. Passing regression tests therefore describe the
tested behavior, rather than establish that deployment work is complete.

## 1. Result summary

| Verification | Result | Evidence |
| --- | --- | --- |
| Full suite run from the installed project | 459 tests + 16 subtests passed; 143.16 seconds | [Installed full results](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/all-tasks-retest/installed-full-results.xml>) |
| Running API, dashboard, authorization and owner session | 58 checks passed; zero failed | [Sanitized live results](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/all-tasks-retest/live-results.json>) |
| Real VirusTotal connection and credentials | HTTP 200; valid analysis returned | [Provider result](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/all-tasks-retest/virustotal-live-results.json>) |
| Independent security/control review | 11 scenarios completed: five controls held and six weaknesses were reproduced | [Diagnostic results](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/all-tasks-retest/independent-diagnostics.xml>) |
| Installed/source integrity | 69 files compared; zero mismatches | Included in live results |

The full-suite XML contains 475 test entries because the 16 subtests are included.
The independent diagnostic scenarios are separate, and some overlap existing
controls. Their passing assertions reproduce observed behavior; they are not
11 additional declarations that the application is secure.

## 2. All 14 responsibilities

“Pass” below refers to the exercised implementation and regression scenarios.
The deployment column identifies real-world checks or dependencies that remain.

| # | Responsibility | What was checked | Result and deployment status |
| --- | --- | --- | --- |
| 1 | Risk logic and UI design | Signal weights, score limits, severity boundaries, partial/Unknown evidence, target handling, consistent dashboard risk display and policy versions. | **Pass.** The live risk-policy endpoint loads. Real-world detection quality and user comprehension remain separate evaluation tasks. |
| 2 | Admin dashboard | Monitoring counts, devices, extensions, findings, risk, alerts, history, reporting and governance screens; empty/error states and role-specific navigation. | **Pass.** The running dashboard is healthy and the owner profile exposes all 20 workspaces. Live API views load successfully. |
| 3 | Security-event logging | Scan and threat events, notification outcomes, alert transitions, actor/reason tracking, linked evidence and governance audits. | **Pass for implemented events.** Authentication failures still lack structured application audit records; see finding S4. |
| 4 | Administrator 2FA | Password and authenticator steps, challenge/session expiry, code replay, lockouts, shared attempt limits, logout, owner provisioning and QR/manual enrollment. | **Pass.** Live owner password + TOTP login and revocation were verified. Managed password/MFA recovery remains absent. |
| 5 | Whitelist and overrides | Exact URL/domain matching, normalization, expiration, owner/admin controls, deactivation, audit records and notification suppression while preserving original risk evidence. | **Pass.** Current rules and audit views load in the live API. Creation/deactivation tests used isolated databases. |
| 6 | Downloaded-file scanning | SHA-256 inputs, uploaded-file hashing, 32 MiB limits, multipart size enforcement, ownership, provider errors, caching, quotas and Unknown handling. | **Pass.** Real VirusTotal file-reputation access was verified. The repository provides backend/dashboard file checks; automatic Chrome download capture is not included. |
| 7 | Monthly reports | UTC month boundaries, aggregation, aggregate-only LLM prompts, saved drafts, retry/idempotency, partial recipient failure, monthly runner and ML evidence in one report snapshot. | **Pass with simulated LLM and email services.** Live generation/delivery is unavailable until LLM and mail settings are supplied. |
| 8 | High-severity alerts | High/Critical triggering, safe payloads, email/webhook adapters, TLS, signatures, bounded timeouts, redirect refusal, destination deduplication and recorded failures. | **Pass with simulated transports.** No SMTP sender, administrator recipients or webhook destinations are configured for live delivery. |
| 9 | Usability and accessibility testing | Walkthrough records, failed/blocked tasks, fix evidence, verified retests, stale-update rejection and dashboard rendering. | **Tracking workflow passes.** Actual user comprehension, screen-reader behavior and accessibility conformance require manual evaluation. |
| 10 | Privacy and data governance | Collection inventory, hostname minimization, privacy revisions, retention preview/confirmation, investigation holds and scan ownership removal. | **Pass for implemented rules.** Personal-history cache protection and a stable account-encryption key need improvement. Live retention deletion was not performed. |
| 11 | Incident response and case management | Scan-linked cases, valid assignees, notes, revision checks, investigation, resolution reasons, reopening and preserved audit history. | **Pass.** Live cases and assignee views load. All lifecycle mutations used temporary data. |
| 12 | Detection quality and false-positive evaluation | Immutable labelled scenarios, dataset digests, baseline comparisons, false positives, misses, Unknown coverage, precision/recall and scoring-review recommendations. | **Pass on synthetic scenarios.** These tests do not establish malware detection accuracy on a real labelled dataset. |
| 13 | Security awareness and in-app guidance | Onboarding and response guidance, current severity thresholds, incomplete assessments, file reputation limitations and role-specific presentation. | **Pass.** Guidance is available through the tested dashboard flows. Effectiveness with actual users has not been measured. |
| 14 | Security policy change management | Immutable drafts, independent review, author self-approval rejection, controlled activation, stale versions and historical scan preservation. | **Pass in isolated two-administrator workflows.** Only the owner is approved in the live installation; a second approved Administrator is needed for independent review. |

## 3. Newer account and ML features

| Feature | Verified behavior |
| --- | --- |
| Account registration | No invitation code is required. Password validation and authenticator verification precede a pending access request. Registration never grants a session or permission by itself. |
| Role assignment | The Head of Administrator exclusively approves/rejects accounts, assigns ordinary roles, changes roles and disables access. Role changes and disabling revoke sessions. |
| Main administrator | Public registration cannot create a second head account; ordinary API actions cannot demote or disable the owner. |
| Normal-user isolation | Personal results cannot be retrieved by a different normal user; submitted device identities are replaced with the server-assigned identity. |
| Manager controls | Report generation/delivery and security-setting writes are denied. Manager governance reads remain broader than visible navigation; see S1. |
| QR enrollment | Generated images decode correctly, match the manual key and produce matching TOTP codes. Expired, cancelled and invalid setup data are cleared. |
| Monthly ML | All 10 focused ML cases pass as part of the full suite: training excludes target/future months; results are reproducible; synthetic activity spikes are flagged; identifiers are excluded; evidence remains consistent in reports; access/date guards and UI fallback work. |

The live ML endpoint returned **insufficient_history** for September 2026, with
**zero active training days**. This is the expected honest fallback. The model
requires at least 30 active historical days and three distinct feature
observations from the 90 days before the selected month. Its output identifies
unusual aggregate activity; it does not establish that a file or URL is malicious.

## 4. Actual deployment readiness

Only the presence of configuration was recorded; no secrets, addresses or
authenticator codes were saved in test reports.

| Dependency or setting | Current state | Consequence |
| --- | --- | --- |
| VirusTotal API key | Present; one real authenticated public-hash lookup returned HTTP 200 | Provider access works. This does not establish every provider outcome or malware detection accuracy. |
| OpenAI API key and model | Both absent from the installed configuration | Live LLM-written monthly summaries cannot be generated. |
| SMTP host, sender and administrator recipients | Absent | Monthly reports and alert emails cannot be delivered. |
| Webhook destination | Absent | High-severity webhook alerts cannot be delivered. |
| Database | SQLite | PostgreSQL deployment, locking and migrations were not exercised. |
| Historical ML activity | Zero active training days | Live anomaly review is unavailable until sufficient history is collected. |
| Approved accounts | One Head of Administrator; zero approved ordinary Administrators, Managers or Normal users | Role tests used disposable accounts. Live independent policy approval cannot be completed yet. |
| Configured independent reviewer | Absent | Add and approve a distinct Administrator to use the independent review workflow. |
| Dedicated account-encryption key | Absent | Registered-account encryption remains coupled to the owner's authenticator secret. |
| Chrome extension and automatic download monitoring | Not included in this repository | Manifest V3 behavior, browser permissions, inline-link marking, RDAP integration and automatic download capture need testing with Basel's extension. |

The live owner check exercised password-only denial, completed 2FA, approved
owner privileges, all available read-only API views, logout and subsequent HTTP
401 for the revoked test session. No actual roles, policies, investigations or
retention settings were changed. No reports or alerts were sent. The provider
check used only the public SHA-256 of an empty file, uploaded no file content and
made no production scan-history entry.

## 5. Security findings reproduced in this run

| Finding | Evidence | Recommended correction |
| --- | --- | --- |
| S1 — Manager API/UI permission mismatch | A manager can read policies, privacy, evaluations and usability via HTTP 200 while those pages are absent from its dashboard profile. | Define the intended manager read scope and derive route permissions and navigation from the same capabilities. |
| S2 — Encryption coupled to owner TOTP | Changing only the owner TOTP secret breaks access to registered factors under the default derived key. A stable dedicated Fernet key avoids that failure. | Use a stable encryption key with a safe migration and restore drill; changing keys without migrating existing ciphertext is unsafe. |
| S3 — Disabled accounts cannot be restored | Disabled users disappear from active and pending lists; no enable endpoint exists and approval cannot reactivate them. | Add an audited, owner-only lifecycle view and restoration action that never revives old sessions. |
| S4 — Missing authentication audit events | A failed password returns 401 without adding a structured governance audit event. | Record sanitized login, MFA, lockout, logout, recovery and authorization outcomes without secrets. |
| S5 — Approval reasons can be almost empty | Seven spaces followed by one character are accepted as the minimum-length reason. | Trim before validation and require meaningful reason text. |
| S6 — Personal history lacks explicit no-store | `/api/my/scans` returns data without an explicit `no-store` cache directive. | Apply the intended cache protection to sensitive authenticated monitoring responses. |

Five additional independent controls held: the head cannot approve its own
policy; managers cannot generate/send reports; two normal users cannot share
personal results; stable encryption survives owner-factor rotation; scan
retention removes personal ownership links.

Previously identified operational gaps also remain: there is no supported
password/MFA recovery workflow, and default 12-hour sessions have absolute
expiry without idle timeout or fresh verification for sensitive actions.
Standalone monitoring-off compatibility mode still exposes the scan API;
the current enabled installation passed its protected-mode tests.
Further context is in [the earlier role review](ExtSecure%20Roles%20Retest%20Report.md).

## 6. Next steps

1. Supply LLM, email and/or webhook settings, then perform a controlled real report/delivery check with designated recipients.
2. Approve a distinct Administrator for independent policy review.
3. Resolve S1 and S2 first, then add recovery, session controls, lifecycle restoration and authentication auditing.
4. Collect enough real aggregate history for ML; use a representative labelled dataset to assess detection quality.
5. Test PostgreSQL and Basel's actual Chrome extension together with the backend; complete phone-import and manual accessibility/user checks.

This run changed only test evidence and documentation. Application code,
passwords, authenticator settings, roles, scans, policies and operational data
were preserved. Tests used fresh temporary SQLite databases, synthetic cases
and mocked external integrations; the live session was revoked after checking.
