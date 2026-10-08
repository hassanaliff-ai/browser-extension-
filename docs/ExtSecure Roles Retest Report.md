# ExtSecure — Role and Access-Control Retest Report

**Review date:** 4 October 2026 (Asia/Riyadh).
**Reviewed installation:** `C:\Users\hassa\browser-extension-`.
**Scope:** Head of Administrator, Administrator, Manager and Normal user; registration, approval, authentication, authorization, account lifecycle, personal scan ownership and dashboard navigation.

The role design is a sound foundation for the project. The core approval and privilege boundaries passed the repeated tests. It is suitable for continued development and a controlled project demonstration. The remaining permission, recovery and operational gaps should be addressed before treating it as a production identity system.

No production permissions or application code were changed during this review. Additional diagnostic tests used temporary databases. The live check authenticated the existing main account, exercised protected operations that were rejected, and revoked its test session. Credentials are excluded from this report and the test result files.

## 1. Results and evidence

| Verification | Result | Duration / evidence |
| --- | --- | --- |
| Complete application regression suite | 440 tests and 16 subtests passed; no failures | 157.55 seconds; [JUnit results](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/rbac-retest-full.xml>) |
| Focused tests executed from the installed copy | 40 passed; no failures | 31.03 seconds; [Installed-copy results](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/rbac-review/installed-results.xml>) |
| Additional independent review scenarios | 11 completed successfully, including diagnostic reproductions of weaknesses | 10.50 seconds; [Independent results](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/rbac-review/independent-results.xml>) |
| Running installation checks | 13 passed, including actual owner password/TOTP sign-in and session revocation | [Live check details](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/rbac/live-check-results.json>) |
| Installed-source integrity | All 26 previously published files matched the reviewed source | SHA-256 comparison |

The installed-copy tests overlap the full suite; they are not 40 additional unique security tests. The 11 independent scenarios include tests that deliberately confirm an undesirable behavior. Their success means the behavior was reproduced, not that the weakness is acceptable. Passing tests do not prove that every possible attack has been excluded.

| Control / workflow | Repeated result |
| --- | --- |
| Registration and verified enrollment | New accounts remain pending; registration does not issue an authenticated session. |
| Main-administrator authorization | Administrator, Manager and Normal user cannot approve/reject requests, change roles or disable other accounts. |
| Two-factor authentication | Password alone and enrollment tokens do not authorize monitoring. Valid fresh TOTP completes sign-in; replay, expiry and lockout checks pass. |
| Reserved main account | Public duplication, disable and demotion attempts are rejected. The approval schema cannot create a second head account. |
| Normal-user isolation | Users cannot read organization monitoring or retrieve another user's personal scan. A second normal user was independently tested against the first user's scan reference. |
| Device impersonation | Normal-user hash checks and uploaded-file checks receive a server-assigned device reference. Submitted foreign device and extension identities are not adopted. |
| Administrator operations | Security workflows remain available; account administration remains owner-only. |
| Manager operations | Managers can investigate incidents and review alerts. Report generation/delivery and security-setting mutations are denied. |
| Role change and account disable | Existing sessions are revoked; disabled users cannot sign in. |
| Policy separation of duties | The Head of Administrator cannot approve their own policy draft. A different approved administrator is required. |
| Legacy scan endpoint | With monitoring enabled, anonymous calls are rejected; approved scanning accounts or trusted machine identity are required. |
| Personal data retention | Eligible scan removal also removes its personal ownership link. |
| Account audit | Approval and role-change records identify the owner. Failed authentication is a separate gap described below. |
| Dashboard permissions | Role navigation and manager reporting controls pass Streamlit execution tests. |

## 2. Assessment of the roles

### Head of Administrator

The single owner account matches the requested governance model: one authority approves access, selects roles and can revoke them. Protecting this account against ordinary disable and demotion prevents accidental administrative lockout through those endpoints. The owner still follows independent policy review; full access should not bypass that safeguard.

The main weakness is operational concentration. Approvals, account recovery and role changes depend on one identity. Keep one main administrator as requested, but add documented recovery and emergency procedures rather than granting routine full access to more people. Use this identity for access administration and exceptional decisions; use an approved ordinary Administrator account for routine security work where practical.

### Administrator

The role provides a useful operational scope: investigations, file checks, exceptions, reporting, policy workflows, privacy/retention and evaluation. Keeping user approval outside this role is a clear boundary.

Some of these operations have a greater impact than ordinary monitoring. Policy activation, retention deletion, exception changes and report delivery should receive explicit confirmation and, where appropriate, fresh authentication. Future granular capabilities can separate these actions without immediately adding more user types.

### Manager

A monitoring and incident-coordination role is useful. Reviewing evidence and reports while leaving configuration and delivery to administrators is a reasonable division of work.

Its current backend read scope is wider than its visible dashboard. This should be clarified and narrowed. In a multi-team deployment, manager access should also be scoped to assigned teams/devices/cases rather than automatically covering the whole organization. That team restriction is an enhancement to the current single-organization design, not a demonstrated normal-user isolation bypass.

### Normal user

Personal checks and history provide useful access without exposing organizational findings. The ownership boundary held in the independent two-user test, and the backend prevents forged device association.

The user experience needs an access-request status page, understandable role descriptions and a way to contact the administrator when approval or recovery is needed. The older authenticated `/scan` endpoint also supports URL and IP checks, while the personal dashboard is presented as file history. Either expose those supported checks clearly and rename the view to personal scan history, or deliberately limit the endpoint to the documented role capabilities.

## 3. Findings and recommended changes

### F1 — Manager API access exceeds the visible workspaces

**Priority: High for clarification and correction of the permission model.**

Independent requests returned HTTP 200 for `/api/policies`, `/api/privacy`, `/api/evaluations` and `/api/usability` using a Manager session. The corresponding dashboard workspaces are absent from that role's profile. Managers cannot mutate those settings, but hiding a page does not remove its read permission.

**Recommended change:** define explicit read permissions for managers. Keep overview, operational findings, scans, alerts, cases and reporting evidence. Remove unneeded governance data, or intentionally expose the approved read-only pages so the API, UI and documented role agree. Use the same capability definitions to derive endpoint authorization and navigation. This follows the least-privilege and per-request authorization principles in [OWASP Authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

**Acceptance check:** each manager read endpoint is explicitly approved or returns 403; dashboard navigation agrees with the approved matrix.

### F2 — Owner MFA changes can invalidate registered-account encryption

**Priority: High; availability and recovery risk.**

When `ADMIN_ACCOUNT_ENCRYPTION_KEY` is absent, registered TOTP encryption derives from the primary TOTP secret. An isolated test changed only that primary secret and reproduced `Account configuration is unavailable` when loading a registered user. A separate test demonstrated that a stable dedicated Fernet key avoids this coupling.

**Recommended change:** move to a dedicated, stable account-encryption key and a documented, tested key-rotation process. For an installation that already has registered accounts, decrypt and re-encrypt their existing secrets as a controlled migration before switching keys. Simply setting a new key would make existing ciphertext unreadable. Back up the key separately and verify restoration.

**Acceptance check:** the owner can rotate their MFA secret without breaking other accounts, and backup restoration recovers encrypted factors.

### F3 — No supported password or MFA recovery workflow

**Priority: High before operational deployment.**

There are no recovery-code, password-reset or authenticator-reset endpoints. The owner has private initial setup details, which can assist manual reenrollment, but that is not a managed recovery workflow. Ordinary users have no comparable supported recovery path. The initial owner setup file also contains both the password and the TOTP seed; retain it only through controlled handoff, then move recovery material into appropriate secure storage and remove the unnecessary plaintext password copy.

**Recommended change:** add hashed, single-use recovery codes and verified owner-controlled recovery for ordinary accounts. Define an audited offline emergency recovery process for the sole owner. A recovery route must not become an easier authentication bypass. See [OWASP MFA recovery guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html).

**Acceptance check:** lost-authenticator recovery succeeds for a verified user, replayed recovery codes fail, all old sessions are revoked and the event is audited.

### F4 — Privileged sessions lack idle expiry and fresh verification

**Priority: High for owner actions.**

The default session lifetime is 43,200 seconds (12 hours). The session model checks absolute expiry and revocation but has no idle-use timestamp or server-enforced idle timeout. Approval and role changes do not require a fresh MFA confirmation after sign-in.

**Recommended change:** add a server-enforced idle timeout and require recent password/MFA verification for approvals, role changes, recovery, sensitive policy changes and retention deletion. A 15-minute privileged idle timeout is a starting product choice to validate with users, not a universal compliance requirement. See [OWASP Session Management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

**Acceptance check:** a stale or idle session cannot perform a privileged action until fresh verification completes; ordinary role changes still revoke all existing sessions.

### F5 — Authentication events are missing from the application audit trail

**Priority: Medium to high for monitoring and investigation.**

An independent failed-password test returned 401 without adding a `GovernanceAudit` event. Password/TOTP success, failure, lockout and session actions lack the structured application audit coverage already present for role changes. HTTP access logs provide request/status information, but do not replace an account-aware security-event history.

**Recommended change:** record authentication successes/failures, MFA failures, lockouts, authorization denials, logout and recovery events with timestamps and appropriate actor/peer context. Never log passwords, OTPs, session tokens, encryption keys or authenticator secrets. See [OWASP Logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

**Acceptance check:** every relevant authentication and authorization outcome generates a sanitized, searchable event; repeated suspicious attempts can produce an administrator alert.

### F6 — Disabled and rejected accounts have no restoration workflow

**Priority: Medium; account lifecycle completeness.**

A disabled user disappears from both the active-account list and pending requests. No enable endpoint exists (404), and using the registration approval endpoint to restore a disabled account returns 409. The username remains reserved, so re-registration is not a substitute.

**Recommended change:** add owner-only lifecycle views for Pending, Active, Rejected and Disabled accounts, with filters and an audited restore action. Require a fresh owner review and explicit role selection. Preserve account identity, prior history and case references; do not revive old sessions.

**Acceptance check:** temporary access suspension and owner-approved restoration work without manual database edits, and disabled users remain barred until restoration completes.

### F7 — Review reasons accept almost-empty explanations

**Priority: Medium; audit quality.**

The eight-character minimum is applied before trimming. The string consisting of seven spaces followed by `x` was accepted as an approval reason. That produces an audit entry but little useful accountability.

**Recommended change:** trim before validation and require a meaningful minimum length for approval and role-change reasons. Add similar validation wherever operational decisions require explanations. Consider an optional verified staff reference so the owner can distinguish a valid colleague from an arbitrary chosen username.

**Acceptance check:** blank and nearly blank reasons are rejected; approval records contain a meaningful reason and verified identity context.

### F8 — Monitoring-off mode exposes the standalone scan service

**Priority: High when deploying beyond localhost; conditional configuration risk.**

The protected installed mode rejects anonymous scan calls. Separately, `main.py` intentionally preserves public standalone `/scan` behavior if monitoring is disabled or the required owner/database configuration is incomplete. This is not a bypass reproduced in the currently enabled installation, but it can conflict with the requirement that scanning users require approval if an operator changes deployment mode.

**Recommended change:** introduce an explicit production mode that refuses startup with incomplete authentication configuration. Retain any public compatibility mode only as a clearly selected development/service mode, with its own exposure and rate-limit policy. Keep machine ingestion credentials out of distributed extensions.

**Acceptance check:** production startup with incomplete access configuration fails closed; no anonymous scan reaches VirusTotal or changes history.

### F9 — Personal history lacks explicit no-store response headers

**Priority: Low to medium; privacy hardening.**

`/api/admin/*` responses receive `Cache-Control: no-store`, but an independent request to `/api/my/scans` did not. This observation does not prove that a browser or intermediary has retained a response; it identifies missing explicit cache protection for personal scan data.

**Recommended change:** apply suitable no-store headers to sensitive authenticated monitoring responses and review browser/session cleanup on sign-out.

**Acceptance check:** personal history, evidence and account responses carry the intended cache policy and another signed-in identity does not see a previous user's data.

## 4. Suggested implementation order

| Order | Work | Definition of completion |
| --- | --- | --- |
| 1 | Resolve the manager permission matrix | UI and API agree; independent allow/deny tests cover every role/resource/action. |
| 2 | Separate the encryption key and design recovery | Existing encrypted factors migrate safely; owner/user recovery and restore drills pass. |
| 3 | Add idle timeout and recent authentication checks | Old sessions cannot authorize sensitive changes; fresh MFA and revocation are tested. |
| 4 | Expand account lifecycle and approval quality | Disabled/rejected accounts remain manageable, restoration is owner-only and reasons are meaningful. |
| 5 | Add account-aware security audit events | Login, MFA, denials, recovery and privilege actions are traceable without secrets. |
| 6 | Enforce production configuration and response privacy | Incomplete authentication fails startup, personal data has explicit cache protection and multi-worker rate limits are configured. |
| 7 | Improve role-specific usability | Approval status, next steps, permission descriptions and supported personal scans are understandable to actual users. |

Do not add more broad roles solely to make the design look more advanced. Keep the three ordinary user types and the protected main owner. Add narrow capabilities and team/data scopes as specific operational needs emerge.

## 5. Practical limits of this review

- Automated persistence checks used SQLite. PostgreSQL locking, concurrent role changes and migration behavior still need testing against a real PostgreSQL deployment.
- The live test verified the main account and protected local endpoints. It did not approve real users, reset factors, send messages, deliver reports or call VirusTotal.
- Reputation, email, webhook and LLM behavior in the regression suite was isolated. Passing those tests is not evidence of live third-party delivery or detection accuracy.
- Dashboard role flows were tested through Streamlit's execution/testing API. This review is not a usability study with independent participants or a screen-reader accessibility certification.
- No Chrome extension exists in this reviewed repository, so extension login, browser identity, automatic download integration and extension-side privilege handling were not tested.
- The sign-in rate limit is process-local. Shared enforcement and correct proxy/peer handling require deployment-specific verification.
- The additional tests reproduced selected edge cases. They are not an exhaustive penetration test or a compliance certification.

## 6. Useful code and test references

- [Role grants and dashboard profiles](<C:/Users/hassa/browser-extension-/src/alba_security/permissions.py:8>)
- [Owner approval, role changes and disabling](<C:/Users/hassa/browser-extension-/src/alba_security/registration.py:65>)
- [Registered account encryption and actor resolution](<C:/Users/hassa/browser-extension-/src/alba_security/admin_directory.py:39>)
- [Session lifetime and verification](<C:/Users/hassa/browser-extension-/src/alba_security/admin_auth.py:108>)
- [Optional monitoring and legacy scan authentication](<C:/Users/hassa/browser-extension-/main.py:138>)
- [Existing role integration tests](<C:/Users/hassa/browser-extension-/tests/alba/test_roles.py>)
- [Independent diagnostic review tests](<C:/Users/hassa/OneDrive/Documents/ChatGPT/Alba Project/.preview/rbac-review/test_independent_review.py>)

**Assessment:** retain the overall role structure. Prioritize consistent permissions, safe recovery and stronger session/audit controls before expanding features or granting wider access.
