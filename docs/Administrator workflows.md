# ExtSecure administrator workflows

The console combines the original eight security responsibilities with six
governance and investigation responsibilities. Each screen uses the existing
backend-enforced password and authenticator session.

## Incident investigations

Open **Incident cases**, choose a stored scan, and assign a configured
administrator. Cases move from Open to Investigating to Resolved. A resolution
requires a reason; reopening preserves the earlier decision in the audit trail.
Notes record the author and time. Updates carry the displayed revision, so a
stale browser cannot silently overwrite another administrator's decision.
Case evidence remains linked to the original findings and scoring version.
Case status does not change alert status or resend notifications.

## Controlled policy changes

**Security policies** shows the active scoring configuration and saved drafts.
Each draft contains all signal weights, severity thresholds, a reason and its
base version. Compare the proposed values before reviewing. Approval requires
a different approved administrator. Activation requires an approved draft
based on the current policy. Concurrent or outdated activation is rejected.
Only future scans use the new configuration; previous scores and evidence are
preserved. Unknown behavior and the score cap cannot be changed by a draft.

The existing administrator remains the primary account. To enable independent
review, run `python -m alba_security.admin_setup --reviewer` and privately set
`ADMIN_REVIEWER_USERNAME`, `ADMIN_REVIEWER_PASSWORD_HASH` and
`ADMIN_REVIEWER_TOTP_SECRET` on the backend. The reviewer needs a distinct name
and authenticator secret. No reviewer account or credentials are generated
automatically. Restart the backend after changing account configuration.
The primary account is the Head of Administrator. After restart, it must approve
the reviewer in Accounts and assign Administrator access before the reviewer
can sign in. Managers and normal users cannot review or activate policies.

## Privacy and retention

**Privacy governance** shows the collection inventory, purpose and scan
retention period. Disabling hostname collection masks existing scan displays
and stores a fingerprint label for new URL scans. Existing hostname values
are not erased retroactively; exact exception targets remain visible to
administrators because they are needed to manage those rules. URL paths,
query strings and uploaded file bytes remain excluded from scan storage.

Preview retention before applying it. The operation removes expired scan
records together with their findings, alerts and security events. A scan is
protected while any incident case is linked to it, including a resolved case,
or an alert is Open or Acknowledged. The operation is manual; no deletion job
is installed. Administrative audits, cases, device/extension inventories,
policies, evaluation fixtures and saved reports remain retained. These records
need an organisation-approved lifecycle before production deployment.
Live monthly statistics can change after retention; a saved report remains a
snapshot. Keep free-text notes, titles and reasons free of private URLs,
credentials, personal details and local file paths.

## Detection-quality evidence

**Detection evaluation** accepts labelled JSON scenarios and a dataset version.
Scenario names must be unique. The server stores the sanitized signal codes
and statuses, an immutable dataset digest, and results for both the baseline
and active policy. Reusing a version with different fixture contents is
rejected. The comparison records true positives, false positives, true
negatives, missed threats, Unknown results, precision, recall and coverage.

The decision threshold is High/Critical. Low/Medium are below that response
threshold; this is not a claim that those findings are harmless. Unknown
predictions are excluded from the confusion matrix and reduce coverage.
Precision or recall is unavailable when its denominator is zero. Synthetic
examples are provided for learning the format, not as evidence of real-world
malware detection accuracy. Download the result JSON to retain review evidence.

New evaluation runs also save scoring-review recommendations linked to the
incorrect or missed scenario names and detected signal codes. Missing checks
remain Unknown. A baseline regression is flagged when either error count rises.
Recommendations describe candidate experiments and their tradeoffs; they do
not change weights or thresholds. Submit any resulting change through the
existing independent policy review and approval workflow. Older saved runs
remain readable and can be rerun with their unchanged dataset to add suggestions.

## Usability and accessibility

**Usability and accessibility** records actual task walkthroughs for keyboard
navigation, contrast, screen-reader behavior, comprehension and workflow.
Failed and blocked tasks start Open. Document a fix before recording a verified
retest. Each change records its administrator and evidence, and stale revisions
are rejected. A checklist and visible keyboard focus support testing across
the original and new screens. This issue log does not establish accessibility
conformance; manual assistive-technology and user testing are still required.

## Security guidance

**Security guidance** provides onboarding and response instructions for risk
levels, incomplete checks, file reputation, exceptions, cases, policy review,
monthly reports and privacy. Severity thresholds come from the active backend
policy. Existing scan evidence also includes a suggested action and scoring
version. The current repository implements backend and administrator console
workflows. It does not automatically inspect browser downloads or include
Basel's Chrome extension implementation.
