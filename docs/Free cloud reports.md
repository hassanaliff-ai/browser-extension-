# Private automatic reports

The owner requires project information to remain in the database. GitHub sends
only an authenticated, empty trigger to Render. It receives HTTP 204 and no
report content, counters, periods, identifiers or database records. The worker
rejects any nonempty successful response and never prints response bodies.

Render reads the existing Neon database, prepares statistics and deterministic
summaries, runs the existing monthly activity evaluation, and saves the results
and run audit to Neon. These summaries are explicitly labelled
`verified_statistics`: **no LLM is used for automatic cloud reports**. Historical
local AI reports are retained and identified separately. Local Ollama and the
older Windows tasks are not required by this automatic reporting path.

## Schedule

- Sunday 09:00 Asia/Riyadh: previous Sunday–Saturday UTC week.
- Day 1 at 09:00 Asia/Riyadh: previous completed UTC month.
- Minute 17 each hour: retry missing periods and queued administrator requests.
- First activation prepares the latest complete week and month, including empty
  periods. The initialization audit anchors later catch-up.
- Unique period keys prevent duplicate reports. Manual weekly requests retain
  their existing Monday-based period convention.
- Monthly ML results preserve insufficient history and unavailable states. They
  are not interpreted as proof of safe activity. No incident decision or block
  release is performed by the report scheduler.

The workflow uses only standard runners for this public repository, with no
paid inference, additional hosting or database credential on GitHub. Its identity
is a short-lived GitHub OIDC token verified against the issuer, audience, fixed
repository/owner IDs, main branch, workflow path and allowed events. It can trigger
preparation, but cannot read accounts, scans or reports. Earlier inference-job
data endpoints were removed. There are no reusable report access secrets.

Free scheduling is best effort. GitHub can delay or drop a trigger and disables
public-repository schedules after 60 days without repository activity. Review the
private scheduler status in Reports and re-enable a disabled workflow in Actions.
Render/Neon quotas and outages still apply. Do not use artificial commits or paid
services to hide these limits. `EXTSECURE_PRIVATE_REPORTS_ENABLED=false` as a
GitHub repository variable pauses future triggers without exposing any data.

The normal Render environment enables the trigger endpoint. Set
`CLOUD_REPORT_AUTOMATION_ENABLED=0` to disable it explicitly. The earlier
`REPORT_AUTOMATION_ENABLED` flag applies to local scheduling only. Reports use
`REPORT_LANGUAGE=en` or `ar`, defaulting to English. The API origin is unchanged.

## Verification

Backend tests verify real RSA signatures, rejected fork/PR identities, empty
responses, database-only persistence, duplicate prevention, calendar boundaries,
catch-up, privacy, failure handling and explicit non-LLM provenance. Worker tests
verify no data is received or logged. The GitHub job must then be run against
the deployed trigger and saved records checked privately in Neon. Fixtures alone
do not establish successful live operation. Personal academic files stay local.

Sources checked 26 November 2026:

- https://docs.github.com/en/actions/reference/security/oidc
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule
- https://render.com/docs/environment-variables#render-environment-variables
