# SecureScope and ExtSecure integration

The root `extension/` is the combined Chrome extension. Do not install the older
`prototypes/securescope/securescope-extension/` alongside it in the same profile.
The prototype remains available as Basel's original contribution and test fixture.

## Included contributions

- Basel's inline-link content script is loaded by the root MV3 manifest. It sends
  only site origins to the ExtSecure worker, labels locally suspicious links,
  observes changed links and bounds page work. It does not submit those links to
  VirusTotal or claim that an unlabelled destination is safe.
- The shared backend uses Basel's RDAP implementation through
  `alba_security.domain_age`. Registration age is evidence in the existing risk
  policy; unavailable age remains Unknown.
- The SecureScope primary API retains ExtSecure authentication, database history,
  role checks and threat containment. Its `/api/v1/check` endpoint is the root
  extension's manual URL-scanning endpoint.
- Basel's offline inline-rule evaluation and its regression tests are included.
  Private datasets, reputation collectors, attempt logs and results are separate
  local material and must not be published as part of this integration.

## Verification commands

From the repository root, using the project's configured Python environment:

```text
python -m pytest -q --basetemp=.private/integration-qa
node --test extension/tests/*.test.js prototypes/securescope/test/*.test.mjs
```

For real Chrome extension checks, install Playwright's Chromium test browser and
run:

```text
node extension/tests/browser-smoke.mjs
node extension/tests/securescope-integration-browser.mjs
```

`EXTSECURE_PLAYWRIGHT_MODULE` may name the installed Playwright module, and
`EXTSECURE_TEST_OUTPUT` sets the private evidence/profile directory. Use a fresh
output directory for each verification run. `PLAYWRIGHT_BROWSERS_PATH` selects a
nondefault test-browser installation.

The inline integration test uses a disposable profile, synthetic local-only
session and an intercepted reserved-domain HTML fixture. It verifies the real
content-script/worker message path, dynamic-link handling and lack of outbound
lookups. It never signs in to the shared API, submits scans, opens suspicious
destinations or writes shared database records. This verifies integration rather
than detector accuracy or production account authentication.

Basel's original Python prototype tests also require the root package on the
Python import path. Install `prototypes/securescope/requirements-backend.txt` in
the test environment, or set `PYTHONPATH` to this checkout's `src` and root before
running `python -m unittest discover -s test -p 'test_*.py'` from the prototype
directory. Avoid testing an older checkout accidentally through another virtual
environment's editable installation.

## Deployment

The public ZIP has its API origin, CSP and navigation exemption configured for
the same HTTPS endpoint. The Git-tracked development sources use loopback by
default; the local deployed copy and public ZIP use the configured release
origin. Keep deployment-only origin changes and credentials out of source
commits.

Updating GitHub does not reload an already running unpacked Chrome extension.
Replace files in its existing folder, reload ExtSecure at `chrome://extensions`
and reopen the console. Preserve the existing profile's storage and device
registration. Public access still requires the API host and HTTPS tunnel to be
running.

## Verification on 14 November 2026

Fetching all published branches found no unmerged Basel commits: every remote
branch tip was already an ancestor of `main` (`25efa32` at verification start).
The local HTTPS deployment settings were saved before pulling and restored
afterward without conflicts. No duplicate prototype extension was copied into
the operational package.

- Complete backend suite: **979 passed, 16 subtests passed, 18 skipped** using
  four isolated pytest workers. Skips were 11 dedicated-PostgreSQL checks, six
  dedicated-database/local-test-administrator checks and one PostgreSQL row-lock
  check. Production PostgreSQL was not used as a disposable test database.
- Combined extension and SecureScope prototype JavaScript: **320 passed**.
- SecureScope prototype Python tests: **20 passed**, using this checkout's root
  and `src` on the Python import path.
- Actual MV3 Chrome startup/console: **four checks passed**.
- Actual inline content-script/worker integration: **five checks passed**.
- Public health and capabilities: **HTTP 200**. Anonymous monitoring/account
  access: **HTTP 401**, as required.
- Release ZIP: integrity verified, version **0.8.53**, fixed HTTPS origin and
  shared inline/RDAP display/runtime assets matched the local extension.

Heavy parallel testing temporarily delayed live API responses on the host.
After the suite finished, health returned HTTP 200 locally and publicly; public
capabilities and unauthorized account checks also passed. The IP, HTTPS hostname,
accounts, device identities and shared scan records were not changed.

These checks do not claim comprehensive live-provider accuracy, remote-device
Chrome permissions or PostgreSQL-specific concurrency coverage. No new
VirusTotal evaluation requests were made, and Basel's private evaluation
materials were not accessed, rerun or published.
