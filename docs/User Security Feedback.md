# User security feedback

Implemented in extension 0.8.30 with PostgreSQL migration 0010.

## Submit a concern

Open a scan from **My file history** or **Scan history**, select **Inspect**,
then expand **Report a concern or challenge this warning**. The same form is
available with new scan results, including the popup.

Choose **Report a suspicious result** or **Challenge a warning** and explain
the concern in 10–2,000 characters. Do not include passwords, personal details,
full URLs, file paths or file contents. The backend assigns the reporter from
the authenticated account; the browser cannot select another identity.

Each account can submit once per scan. Duplicate submissions return a clear
409 response. A submission never changes the risk score, releases a block,
approves website access or creates an exception.

## Review and follow up

The extension console includes **Investigate → User feedback**. Normal users
and managers see only their own submissions. Administrators and the head
administrator see all submissions and can review them.

Administrators inspect the original scan and record one outcome:

- Threat confirmed.
- Warning appears incorrect.
- More evidence needed.

A review requires an explanation. The backend records the reviewer, UTC time
and revision. Concurrent or repeated decisions are rejected with 409 rather
than overwriting another administrator's review. Users can see the saved
decision in the same workspace. Filters and pages of 50 records support review
without downloading the entire history.

Normal users can reference only scans assigned to their account. Managers and
administrators can submit concerns about organization evidence their role can
inspect. Only administrator roles can record review decisions. Every endpoint
requires a valid completed two-factor session; ingestion credentials and
password-only challenges are rejected.

## Evidence and privacy

`user_security_feedback.scan_id` references the original `scans` record. Database
constraints validate categories, status, review consistency and duplicate
submissions. Original evidence and containment remain unchanged even when the
review outcome is a possible false positive. Any release uses the existing
separate investigation and threat-release workflow.

Submitted text and review explanations remain in the access-controlled feedback
table. Audit entries record submission/review metadata, without copying free
text. Hostname display follows privacy settings. Feedback-linked scans are held
out of ordinary scan retention, including after review, preserving the review's
evidence link. This hold is disclosed in the privacy screen.

## Verification

- Backend authentication, ownership, administrator review, duplicate handling,
  stale revisions, privacy, pagination, retention and SQL constraint checks.
- Real PostgreSQL tests run only in a generated disposable test database.
- JavaScript route allowlist, escaped rendering and request-body tests.
- Real MV3 Chrome test: user submission, administrator review, source inspection,
  unchanged Critical containment, narrow layout, saved decision after sign-in,
  and no page JavaScript errors.

Run backend tests with `pytest tests/alba/test_user_feedback.py`. The scripts
`verify_feedback_postgresql.py` and `verify_user_feedback.py` run isolated
PostgreSQL and Chrome integration checks. Browser verification requires Node,
Playwright and Chromium configured on the test machine. Screenshots and test
databases remain under ignored `.private/`, never in the distributed ZIP.
