# Free cloud reporting

Weekly and monthly reports no longer need Windows or laptop Ollama. The GitHub
`Cloud security reports` workflow runs a pinned Qwen2.5 7B model on a standard
public-repository Ubuntu runner, then submits the draft to the existing Render
API. Neon retains the report and the immutable run audit. No paid compute, AI API
key or database password is supplied to GitHub. Do not change the job to a paid
runner or make assumptions about private-repository billing.

## Schedule and recovery

- Sunday 09:00 Asia/Riyadh: previous Sunday–Saturday **UTC** week.
- Day 1 at 09:00 Asia/Riyadh: previous completed **UTC** month.
- Minute 17 each hour: retry missing reports and catch up after outages.
- First activation bootstraps the latest closed week and month, including empty
  periods. The initialization audit anchors subsequent catch-up, so missed periods
  are not silently replaced by only the most recent period.
- One workflow at a time and unique database period keys prevent duplicate saved
  reports. Evidence changed during inference causes a fresh-snapshot retry.
- Monthly preparation also saves the existing monthly ML activity review. Missing
  training history remains `insufficient_history`, never a fabricated assessment.

Free scheduling is best effort, not an uptime or exact-time guarantee. GitHub may
delay or drop scheduled triggers. Public-repository schedules are disabled after
60 days without repository activity. Review the cloud worker contact and run
status in Reports; re-enable a disabled workflow from Actions. Do not manufacture
commits or bypass service quotas to hide this limitation. Render/Neon quotas and
outages still apply. Paid services are not enabled as a fallback.

## Trust and privacy

Render validates GitHub's short-lived RS256 OIDC token against the fixed issuer,
audience, repository and owner IDs, main branch, exact workflow path and approved
events. A token from a fork, pull request, different workflow or user session is
rejected. It grants only aggregate report preparation and validated report writes.
It cannot read individual scans or change accounts, approvals, incidents or blocks.

Only fixed-category aggregate statistics enter the ephemeral inference job. Raw
URLs, names, device IDs, page/file content, alert archives and credentials remain
off the runner. The worker does not print prompts, summaries, HTTP bodies or job
tickets and does not upload result artifacts. The backend signs a snapshot ticket,
rechecks the counts and validates the narrative before saving. Numeric statistics
are authoritative; LLM text remains a review-required draft. No incident is closed,
block released or threat verdict changed by this reporting workflow.

Render enables this integration automatically when its standard `RENDER=true`
environment marker is present. `CLOUD_REPORT_AUTOMATION_ENABLED=0` disables the
cloud endpoints and status; setting it to `1` explicitly enables them. The older
`REPORT_AUTOMATION_ENABLED` setting controls local Windows scheduling only.
`REPORT_LANGUAGE` is `en` or `ar` and defaults to English. The API address stays the
same. A new extension package is needed to show the improved cloud-specific copy;
older clients can still read the saved report history and schedule endpoint.

The report model is Apache-2.0 Qwen2.5 7B, not a newly trained model. Its manifest
digest and Ollama runtime archive are pinned and checked. No alternate provider
or model is selected silently.

## Verification

Run backend regression tests plus `tests/alba/test_cloud_reports.py`; run the
extension's intelligence UI tests. After deployment, dispatch the workflow and
verify a real model-generated report in Neon and the authenticated Reports view.
Offline fixtures do not establish a successful cloud run. Keep real logs and
database evidence private. Personal documents are not published.

Sources checked 26 November 2026:

- https://docs.github.com/en/actions/reference/security/oidc
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule
- https://ollama.com/library/qwen2.5:7b-instruct-q4_K_M
- https://github.com/ollama/ollama/releases/tag/v0.40.18
- https://render.com/docs/environment-variables#render-environment-variables
