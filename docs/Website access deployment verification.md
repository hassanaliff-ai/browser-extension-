# Website access deployment verification

Version 0.8.52 retains administrator self-review and peer review, and checks that
the running API has loaded that policy. Administrators and the head
administrator may approve or reject their own website requests and requests
from other active roles. Managers may review normal-user requests. Account
registration approval retains its existing separate hierarchy.

## Verify the running backend

The API `/health` response must include:

```json
{"website_access_policy":"administrator-self-review-v1"}
```

A successful HTTP health check alone does not establish that a source update
was activated. The extension now distinguishes a reachable older backend with
an **API update required** state, and Website Access explains the mismatch.
Refreshing Chrome alone cannot replace code already loaded by a Python worker.

## Running API deployment

The updated worker runs on loopback port 8769 and the existing fixed HTTPS
hostname proxies to it. It shares the existing PostgreSQL database, account
configuration and authenticator settings. The protected legacy worker on 8765
is left in place for compatibility. Legacy URLs still targeting that worker
need the current fixed-HTTPS extension package to use the updated API.

`scripts/current_api_supervisor.py` monitors the updated worker and starts it
again after failure, without terminating unrecognized processes. The existing
Windows task **ExtSecure API Supervisor** delegates to this controller when
the updated port is selected. Its existing limited S4U identity and startup,
sign-in and retry triggers are retained, so the API can start before sign-in.
The temporary sign-in-only migration task was removed after confirming the
existing background task owns supervision. The host must remain powered on
and connected for public access.

With `EXTSECURE_ACTIVE_API_PORT=8769`, the ordinary Start ExtSecure launcher
uses this worker and supervisor. The legacy supervisor still reports older
website permissions without automatically restarting a healthy API. Startup
verifies the expected policy rather than accepting any process answering the
port.

The extension displays administrator self and peer review controls consistently,
including when an older queue response marks those requests as non-reviewable.
This only determines which controls are visible. The API authorizes every
submitted decision; the extension does not bypass a server rejection or show
an unsuccessful decision as saved. Full self-review requires the updated
backend policy to be running.

## Queue and packaging fixes

Pending unexpired requests appear before completed or expired history, so newer
completed records do not hide an administrator's pending request. The queue
continues to return at most 200 records.

`EXTSECURE_RELEASE_ORIGIN` optionally preserves an existing fixed HTTPS address
in generated ZIPs. It does not change network configuration. A temporary tunnel
recovery will not silently replace that configured release address. LAN ZIP
generation replaces the configured CSP origin and avoids duplicate instruction
files and API navigation rule IDs.

Website reviews still require a reason, explicit destination/business-need
confirmation and the current revision. Decisions are audited. Existing active
threat blocks require investigation and explicit release before access can be
approved; website approval alone does not dismiss a detected threat.

## Validation

- 300 extension JavaScript checks passed.
- 54 website access, approval hierarchy, confirmation, duration and threat-blocking
  checks passed on the final permission implementation.
- 37 supervisor, readiness and process-identity checks passed after the final
  maintenance changes.
- Four isolated Chromium checks passed for MV3 loading, a clean signed-out
  profile, visible outdated-backend detection and the desktop sign-in layout.
  Before deployment they reported an outdated policy; after deployment the
  real extension worker reported the current policy through the fixed HTTPS
  address. Role-session tests verify the review decisions separately.
- The wider initial backend run had 956 passes, 18 skips and three import
  errors caused by loading pre-edit modules during the ongoing edit. The three
  affected activation tests passed in a fresh process and in the final
  maintenance check set. Skipped PostgreSQL tests require a dedicated disposable
  test database; production database integrity was checked read-only.
