# Website access administrator reviews

ExtSecure 0.8.51 allows approved administrators and the head administrator to
approve or reject their own website access requests and requests from any other
active role. Managers can review normal-user website requests; normal users
cannot review requests.

The backend calculates `can_review` for the queue and enforces the same rule
when a decision is submitted. Account registration approval still follows its
existing hierarchy; this change only affects website access.

Every decision requires confirmation that the destination and business need
were reviewed, a reason, and the current request revision. Decisions record the
reviewer and whether this was self-review. Expired or previously reviewed
requests cannot be reviewed again. Temporary grants remain 24 hours or 7 days;
permanent approval adds the destination to the whitelist. Active threat blocks
must still be investigated and explicitly released before approval.

Validation: 51 backend tests passed across website access, role hierarchy,
confirmation, duration and threat containment, including a separate peer-review
check. 46 JavaScript access, core and interface checks passed.

Deployment requires the updated backend and extension files. Existing unpacked
Chrome installations need Reload at chrome://extensions after replacing files.
