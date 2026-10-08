# API 0.4.1: workflow automation and control-effectiveness support

The existing new-task APIs were present in the running monitoring service. This update makes their compatibility and runtime readiness explicit, aligns the main and monitoring API versions, points the main documentation to the mounted operations documentation, and fixes pausing rules after an operator account is revoked.

Integration endpoints:
- Public discovery: `GET /extension/capabilities`. Returns version, monitoring availability/base/docs, operation capabilities and workflow-runner-started state. It exposes no account, incident or credential information. Monitoring-disabled deployments report no operation capabilities.
- Private readiness: `GET /monitor/api/operations/status`. Requires manager/administrator/head administrator and a completed 2FA session. Returns supported operation features, runner state and interval, in-app notification channel and supported evaluation periods. Stopped/failed runners report degraded readiness; normal users are rejected.
- Existing operation paths remain under `/monitor/api/workflow/*` and `/monitor/api/controls/*`.

Existing rule settings can be preserved when pausing after an operator is revoked. Re-enabling or changing recipients still requires active eligible accounts. Revision checks remain enforced. Existing `/health`, `/scan`, sign-in and 2FA response contracts remain intact.

Validation on 8 October 2026:
- 104 backend tests passed across operations, server-owned roles and the main scan API, including new readiness authorization, mounted/public discovery, monitoring-disabled behavior and revoked-account pause/reactivation checks.
- 196 extension tests passed, including the service-worker path allowance for the private readiness endpoint and rejection of POST to it.
- Rebuilt and CRC/hash-verified the extension ZIP: 31 runtime files, extension version 0.8.8. The backend patch version is 0.4.1; no new Chrome permissions or dependencies were required.

Tests used temporary databases and synthetic credentials; they did not send real notifications or alter production account roles. Installed files are copied with backups and private configuration hashes verified. The running API is checked after restart for both versioned schemas, supported task paths, runner-started discovery, anonymous rejection from private readiness, and preserved legacy health behavior.
