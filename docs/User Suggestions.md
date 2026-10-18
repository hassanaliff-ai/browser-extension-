# User suggestions

Extension 0.8.31 adds **Support → User suggestions**. A suggestion is independent
of a security scan; users can propose product improvements without selecting
scan evidence.

## User workflow

Submit a title (5–160 characters), category and description (20–3,000
characters). Categories cover features, interface improvements, accessibility
and other improvements. Explain the benefit without entering credentials,
personal details or private browsing information.

Normal users and managers see only their own suggestions and the administrator's
latest response. Administrators and the head administrator can review all
suggestions and also submit their own. Every endpoint requires completed
password/authenticator sign-in and follows the existing device-access controls.

## Administrator review

Suggestions start as **New**. Administrators can set **Under review**, **Planned**,
**Completed** or **Declined**, with a required explanation (10–2,000 characters).
The author can return to the same workspace to see the current status and
response. Filters and pages of 50 records keep the list manageable.

Changing a status records the reviewer, UTC timestamp and revision. A stale
revision is rejected instead of overwriting another administrator's response.
Status transitions are audited without copying the suggestion text or response
into the audit log. Repeat submission of identical content by the same account
returns a useful duplicate warning. Reporter identity comes from the authenticated
session and cannot be supplied by the client.

Suggestions do not change scores, grant access, release threat blocks or restore
the removed policy/incident automation. No suggestion is published to other
ordinary users, sent to an LLM or emailed automatically.

## Storage and verification

PostgreSQL migration **0011** adds `user_suggestions` with indexes, duplicate
protection and checks for categories, statuses, text lengths and review state.
Suggestions are stored independently of scan-retention deletion.

Tests cover authenticated access, per-user isolation, administrator-only review,
duplicate requests, stale revisions, input validation, database constraints,
UTC dates and unchanged risk configuration. The MV3 Chrome test covers submission,
escaped content, administrator response, a narrow viewport and the author's
return visit. Test accounts and evidence use isolated databases and browser
profiles rather than the user's live records.
