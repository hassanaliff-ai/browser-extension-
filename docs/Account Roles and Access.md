# ExtSecure account roles and approval

The primary `ADMIN_USERNAME` account is the **Head of Administrator**. It is the
single owner identity, protected against self-disable, demotion and public
registration. The setup tool defaults to `head-of-administrator`. Existing
deployments retain their primary account credentials and receive the owner role.

| Role | Access |
| --- | --- |
| Normal user | Check file hashes or upload files for hashing, review only their own file-check history and evidence, read security guidance, view their own account. |
| Manager | View organization monitoring, scans, findings, devices, extensions, events, monthly statistics, saved reports and ML results. Review alerts and create, assign and update incident cases. Cannot change security configuration, deliver reports or manage accounts. |
| Administrator | Security operations, file checks, exceptions, report generation and delivery, policy workflows, privacy and retention, detection evaluation, usability testing and incident cases. Cannot approve users, assign roles or revoke other users' access. |
| Head of Administrator | All administrator workflows plus sole authority to approve or reject requests, assign roles and disable access. Independent policy review still requires a different approved administrator. |

Registration requires a password of at least 12 characters and verified TOTP
enrollment. It creates a pending account, never a session or an active grant.
Only the owner can approve it and select one of the three ordinary roles.
There is no invitation code and no self-service role selection. Every role
uses password plus authenticator verification at sign-in.

Additional accounts configured with `ADMIN_REVIEWER_*` also enter pending review.
Their presence in server configuration does not bypass owner approval.

The backend checks the current role and owner approval on every protected
request. Route permissions are explicit and unlisted routes are denied. Role
changes and account disable operations revoke existing sessions. Approval,
rejection, role changes and disable actions are recorded in the audit log.
Public registration rejects extra role fields and the approval schema cannot
assign another owner. Pending, rejected, disabled and unapproved accounts cannot
use existing sessions to bypass approval.

Normal-user file checks receive a server-assigned personal device reference.
Submitted device and extension identities cannot impersonate another workstation.
Personal history joins scans with authenticated ownership; another account's
personal scan reference returns 404. Organization monitoring remains restricted
to managers and administrators. Trusted ingestion uses a separate machine token
and does not claim personal ownership.

On upgrade, earlier active registered accounts without owner-approval metadata
return to pending review. Their hashes, encrypted authenticator secrets and
historical data remain intact. The primary owner retains access and can approve
them with the appropriate role. Retention deletes personal ownership links with
their scans.

The account workspace is owner-only. It lists pending requests and approved
accounts, explains privileges, allows explicit role selection on approval, and
supports role changes and revocation. The dashboard fetches its navigation from
the authenticated backend profile on every run. Manager reports display analysis
and saved reports while hiding generation and delivery controls.

## Verification

Automated tests exercise all protected read routes and restricted write routes,
real password/TOTP sessions, owner-only account management, head-account
protection, personal-file isolation, upload ownership, manager investigations,
audit records, session revocation, legacy migrations and role-specific Streamlit
screens. External notification and reputation services are isolated in tests.

Deployment secrets belong in private server configuration. Use
`python -m alba_security.admin_setup` to create a primary account for a fresh
deployment, then store the emitted values privately and enroll its authenticator.
Never distribute the owner password, TOTP secret or machine ingestion token in
the extension or dashboard frontend.

Verified on 4 October 2026: 440 tests and 16 subtests passed in 133.91 seconds.
