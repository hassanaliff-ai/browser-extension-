# ExtSecure account roles and access

The configured ADMIN_USERNAME account is the Head of Administrator. It is protected against self-disable, demotion and duplicate public registration. All account roles use a password plus backend-verified authenticator code. QR enrollment is rendered locally.

| Account role | Main privileges |
| --- | --- |
| Normal user | Own file checks/history, website access requests, security guidance, own scan-linked feedback, suggestions and own account/device registration. |
| Manager | Organization monitoring and inventory, reports for review, incident investigation/notes and alert handling; approval of normal-user registrations. |
| Administrator | Security operations, exceptions, reporting/delivery, privacy, detection/usability evaluation, incident protection and manager/normal-user approval. |
| Head of Administrator | All administrator functions, administrator approvals, existing-account role changes and account disabling. |

The approval pyramid is normal user → manager → administrator → head administrator. A higher role can approve lower roles; accounts cannot approve their own registrations. Only the head changes existing account roles or disables access. Account roles and permissions are checked by the backend on each request, including queued AI jobs and device-dependent actions.

Registration is completed once: choose a password, verify authenticator enrollment, then wait for approval. Only completed authenticator enrollments appear in Accounts → Pending registrations. Approved accounts have unlimited validity and no expiry date. Sessions normally last 24 hours; an expired session requires login using the same account, not registration. Temporary enrollment and sign-in challenges have separate short security deadlines.

Disabling an account explicitly denies future login and revokes its current sessions. Version 0.8.38 requires a strict confirmation and an 8–500 character reason at the backend. The extension clears an earlier confirmation/reason when the selected account, role or action changes. Account disable reasons are recorded in append-only audit history. Passwords, bearer tokens and authenticator secrets are excluded from audit records.

Changing roles revokes existing sessions. Pending, rejected and disabled accounts cannot bypass approval through old sessions. Approval chains fail closed if an approving account no longer has the required role. Manually deleting an account is separate from session expiration and must follow the owner's explicit request.

Device enrollment is separate from account registration. Approved accounts can add a Chrome profile; lower-role devices wait for administrator approval and are visible in inventory while pending. Full extension inventory requires Chrome's management permission. A paired device can send narrow heartbeat/inventory updates without an account session; it cannot use that device key as an account login or read account data.

Normal-user evidence is ownership-filtered. Managers and administrators receive only the routes granted to their roles. Removed policy-approval, assignment/escalation automation and advanced database-monitoring features remain outside scope.
