# ExtSecure browser extension and backend

## PostgreSQL database

The local database now uses PostgreSQL with verified migration of the existing
records. See [database setup, schema, queries and verification](docs/PostgreSQL%20Database.md).
The API uses a restricted application role; private credentials and backups stay
outside Git. SQL artifacts are in `sql/` and database integration tests in `tests/alba/`.
The database upgrade adds device/extension attribution constraints, cursor-based
history queries, eight reporting views and a read-only health check. Existing
PostgreSQL deployments should run `scripts/upgrade_postgresql.py` with the configured
local owner credentials before starting the updated API.

Database operator tools now provide private scheduled backups and isolated restore
tests, synthetic performance benchmarks, checksum-tracked SQL migrations, aggregate
basic migrations, and allowlisted JSON/CSV export. See
[database operations](docs/Database%20Operations.md) for commands and scheduling.

One FastAPI process serves the original ExtSecure VirusTotal lookup API and
the Alba risk and monitoring service. The existing `POST /scan` contract remains
at the root. When monitoring is configured, administrator and ingestion routes
are mounted at `/monitor`. The Manifest V3 Chrome extension in `extension/`
provides the main user interface: a toolbar popup and an extension-owned
administrator console. FastAPI remains a separate security backend. The earlier
Streamlit dashboard is retained for compatibility and is not required to use the
extension.

## Chrome extension 0.8.11

The extension console uses teal navigation and option bars, with Light, Dark and
Use device setting appearance choices. Settings saves appearance alongside
language, time zone and table size in Chrome local storage. The console header
has a quick Dark mode toggle; the popup, sign-in and blocked-page screen use the
saved choice. Risk badges, scores and approval controls keep their original meaning.

Every approved account can upload or remove a profile logo in **My account**.
Logos remain local to that account in the current Chrome profile. **Security events**
identifies the linked device, verified scanning user and privacy-safe target reference.
**Table size** offers Compact, Standard and Spacious layouts without hiding records.
See [extension instructions](extension/README.md) for installation and feature details;
[0.8.3 appearance verification](docs/Release%200.8.3%20Appearance%20Verification.md)
and [0.8.2 console verification](docs/Release%200.8.2%20Console%20Verification.md)
document earlier design checks. Reload ExtSecure and reopen its console after updating.

Website and account approval follow a server-enforced role pyramid: managers
approve normal users, administrators approve managers, and the head administrator
approves administrators. Higher roles can also approve lower roles. Only the
head may approve or reject their own website requests. Account registration
allows requesting a role, but never grants it before a higher-role review.
Active approval chains are rechecked on each authenticated request; an inactive
or invalid supervisor chain denies access. Existing account role changes remain
restricted to the head. Self-review decisions are recorded in the audit log. New website approvals offer
24 hours, 7 days, or Forever (whitelist). Temporary access is reusable until expiry;
permanent access continues until revoked, without repeat approval requests.

## AI features in 0.6

Version 0.6 adds bounded public page/text-file reading, structured LLM risk
explanations and recommendations, and complete weekly/monthly alert and
explanation snapshots. See [AI runtime setup](AI_INTEGRATION.md). The existing
Reports extension view contains the new period-report section. The
backend supports local Ollama (`LLM_PROVIDER=ollama`, `OLLAMA_MODEL`) or
OpenAI (`LLM_PROVIDER=openai`, `OPENAI_API_KEY`, `OPENAI_MODEL`) for real generation;
missing settings produce an explicit unavailable result instead of a fake
AI summary. No model was trained from scratch.

Version 0.5 adds English/Arabic with RTL, saved IANA display time zones including
UTC/KSA, and backend-approved website access. The packaged Chrome navigation
rule blocks new HTTP/HTTPS top-level visits until an authenticated account gets
a reviewed one-visit or expiring URL whitelist approval. The role pyramid
controls review authority; only the head can review their own website requests. Whitelist
visits are revalidated against the backend, without permanent browser bypass
rules. Monthly reporting boundaries remain UTC. See `extension/README.md` for
permission scope, privacy, installation and native Chrome smoke checks.

Start the configured backend on `127.0.0.1:8765`, then open `chrome://extensions`,
enable Developer mode, choose **Load unpacked**, and select this project's
`extension` folder. Pin ExtSecure to the toolbar. Sign in with your approved
account and authenticator; **Open console** opens a `chrome-extension://` page.
It does not open a hosted dashboard or a Streamlit application.

The extension has a bundled navy/mint interface, consistent risk states,
keyboard focus indicators, labelled forms, filterable evidence tables and clear
empty/loading/error states. It connects your existing administrator, reporting,
incident and governance workflows to the backend. Passwords, API keys and TOTP
secrets are not stored by the extension. Session tokens are held in Chrome's
memory-only `storage.session`, restricted to trusted extension contexts.

URL checks use the origin by default. Query strings, fragments and embedded
credentials are excluded; a page path is included only when selected. Downloaded
files up to 32 MiB are hashed locally; only SHA-256 is sent to the backend.
This release performs checks on demand. It does not automatically monitor
browsing, read download files, inspect installed third-party extension code,
or provide the separate RDAP/inline-link integration.

See [Chrome extension setup and verification](extension/README.md) and
[Extension verification](docs/Extension%20Verification.md). Managers' backend
read grants now match their visible workspaces: governance and exception data
remain unavailable to that role.

## Security console 0.3

The sign-in screen offers **Log in** and **Register new account**. New users
choose a password of at least 12 characters, enroll an authenticator and verify
a code within 15 minutes and request **Administrator**, **Manager** or
**Normal user** access. Their account remains pending until a higher role approves
it. There is no invitation code and requesting a role does not grant privileges.
Every role signs in with a password and a fresh authenticator code.

Authenticator setup shows a locally generated **QR code**, with **Enter the
setup key manually** as a fallback. Both enroll the same TOTP authenticator;
password and code verification remain separate, required backend steps.
To export the current owner's private QR setup without changing credentials,
run `python -m alba_security.provision_head --env .env --export-qr` on the server
and open the generated offline page in `.private`.

The primary configured account is the protected Head of Administrator and has
full access. Managers review normal-user registrations, administrators review
manager registrations, and the head reviews administrators. Only the head changes
existing roles or disables account access. Administrators run security workflows; managers monitor findings,
review reports/ML results and manage alerts and incident cases; normal users
check files and review only their own results, account and security guidance.
Role changes and disabling revoke existing sessions. Backend route checks
enforce permissions independently of the filtered dashboard navigation.
See [Account roles and access](docs/Account%20Roles%20and%20Access.md).

Passwords use Argon2id. Authenticator secrets use Fernet encryption;
enrollment tokens and sessions are stored as hashes. Set a dedicated
`ADMIN_ACCOUNT_ENCRYPTION_KEY` before registering your first account if desired.
Otherwise encryption derives from the primary authenticator secret. Preserve
the chosen key with backups; changing it without migrating encrypted secrets
prevents account login. Authentication responses carry `Cache-Control: no-store`.
Deployments use HTTPS and shared ingress rate limits.

Earlier active registered accounts without owner-approval metadata return to
pending review on upgrade. Their credentials and history remain intact. Configured
reviewers also need owner approval. Legacy invitation endpoints are retired;
old invitation/enrollment records are preserved but their codes cannot be used.

The console now provides a single investigation workflow across the eight
security responsibilities and the six additional investigation and governance roles:

| Area | Available workflow |
| --- | --- |
| Risk and interface design | Branded console, consistent severity colors, live scoring policy, evidence and recommended next steps. |
| Administrator dashboard | Pending-review count, 14-day UTC activity, devices, extensions, findings and scan history. |
| Security-event logging | Scan evidence and an audit trail showing the administrator, reason and before/after alert status. |
| Administrator 2FA | Separate password and authenticator steps, expiring sessions, replay protection and per-client attempt limits. |
| Whitelist and overrides | Expiring, audited exact URL/domain exceptions; original risk evidence remains visible. |
| Downloaded-file checks | Administrator SHA-256 lookup or a file upload up to 32 MiB; only the hash goes to VirusTotal. |
| Reports | UTC statistics, separately labeled AI narrative, saved drafts, and retries for recipients who have not accepted delivery. |
| High-severity alerts | Email/webhook delivery outcomes plus acknowledge, resolve and reopen actions with review notes. |
| Usability and accessibility | Actual walkthrough records, issue tracking, documented fixes and verified retests. |
| Privacy and data governance | Data inventory, collection purpose, hostname minimization and retention preview with investigation holds. |
| Incident response and cases | Scan-linked cases, administrator assignment, notes, audited status changes and resolution reasons. |
| Detection quality evaluation | Immutable labelled datasets, baseline comparisons, false positives, missed threats and separate Unknown outcomes. |
| Security awareness | In-app onboarding and response guidance using current scoring thresholds. |

Keep `dashboard.py`, `dashboard.css`, and `.streamlit/config.toml` together when
copying the dashboard. Start it from this project directory to load the theme.
Also copy `dashboard_governance.py`, which supplies the six new console views.
The console uses real backend results; an unavailable lookup remains **Unknown**.

See [Administrator workflows](docs/Administrator%20workflows.md) for the new
screens, incident investigation, retention scope and evaluation interpretation.

## Setup

Monthly reports now include an **Isolation Forest** activity review. Use
**Run monthly ML analysis** within Reports to inspect daily results and
download evidence. Training uses the 90 UTC days strictly before the selected
completed month, with at least 30 active days and three distinct observations.
Features are log scan volume, High/Critical fraction and Unknown fraction.
Sparse history produces an explicit unavailable assessment. Unusual activity
does not establish a threat, and scan risk scores are unchanged.

LLM draft generation saves the same ML evidence in the report's statistics and
includes a constrained ML summary in the prompt and delivered report body.
Saved reports remain immutable snapshots; previously saved reports are not
regenerated. Administrator review and the existing email-delivery controls remain
in place. Install the updated requirements to provide scikit-learn.
Implementation reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

1. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # macOS/Linux
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt          # backend, monitoring, and dashboard
   pip install -r requirements-dev.txt      # the above plus test tools
   ```

3. If you do not already have a `.env`, copy `.env.example` to `.env` and fill
   in the values you need. Keep an existing `.env`; setup must not overwrite it.
   The API process reads `.env` from the project directory. The minimum setting
   for the original `/scan` route is `VT_API_KEY`; the app refuses to start
   without it. `CACHE_TTL_SECONDS` optionally changes its in-memory cache time
   (default 600 seconds).

4. To enable `/monitor`, set `DATABASE_URL`, `ADMIN_USERNAME`,
   `ADMIN_PASSWORD_HASH`, and `ADMIN_TOTP_SECRET` together. Monitoring stays
   unmounted if those settings are absent, while the original `/scan` continues
   to work. Set `MONITORING_ENABLED=0` to keep it unmounted even when those
   settings are present. Use PostgreSQL for deployment, or
   `sqlite:///./extsecure.db` for a local trial. Create an administrator password
   hash and authenticator secret
   with:

   ```bash
   python -m alba_security.admin_setup
   ```

   The command prompts for a password, then prints values to put in `.env` and
   an enrollment URI for an authenticator app. Set a long random `INGEST_TOKEN`
   when a trusted external service will call the monitoring ingestion routes.
   If omitted, the server creates a private token for that run, so external
   callers cannot use those routes.
   Keep the token and all API keys on the server; do not bundle them in a browser
   extension.

## Run

Start the development server with auto-reload:

```bash
uvicorn main:app --reload
```

The API will be available at http://localhost:8000.

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Monitoring health, when enabled: http://localhost:8000/monitor/health

To run the administrator dashboard in another terminal:

```bash
streamlit run dashboard.py
```

The dashboard defaults to `API_BASE_URL=http://localhost:8000/monitor`. Set
that environment variable in the dashboard terminal if the API uses a different
address. Each dashboard viewer signs in with the administrator username and
password, then a fresh six-digit authenticator code.

## API

### `GET /` and `GET /health`

Liveness check. Returns `{"status": "ok", "service": "TestAPI"}`.

### `POST /scan`

Scans a URL, file hash, or IP address with VirusTotal and returns a simplified
verdict plus the raw engine counts.

**Request body**

| Field       | Type   | Required | Description                                                                 |
| ----------- | ------ | -------- | --------------------------------------------------------------------------- |
| `target`    | string | yes      | What to scan (must be non-empty and valid for `scan_type`).                 |
| `scan_type` | string | no       | `"url"` (default), `"hash"`, or `"ip"`.                                     |

Target formats:

- `url`: an absolute `http://` or `https://` URL.
- `hash`: an MD5, SHA-1, or SHA-256 hex digest.
- `ip`: an IPv4 or IPv6 address.

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "url"}'
```

**Response (200)**

```json
{
  "target": "https://example.com",
  "scan_type": "url",
  "verdict": "harmless",
  "malicious": 0,
  "suspicious": 0,
  "harmless": 62,
  "undetected": 28,
  "cached": false
}
```

| Field                                            | Description                                                   |
| ------------------------------------------------ | ------------------------------------------------------------- |
| `verdict`                                        | `"malicious"`, `"suspicious"`, or `"harmless"` (see below).   |
| `malicious`, `suspicious`, `harmless`, `undetected` | Raw engine counts from VirusTotal, unmodified.             |
| `cached`                                         | `true` if served from the local cache instead of VirusTotal.  |

**Verdict thresholds**

A single stray engine flag is common (even well-known sites get one or two), so
the verdict requires several engines to agree:

| Verdict      | Rule                                                        |
| ------------ | ----------------------------------------------------------- |
| `malicious`  | `malicious >= 3`                                            |
| `suspicious` | `malicious` is 1 or 2, **or** `suspicious >= 3`             |
| `harmless`   | anything else                                               |

**Errors**

Errors return `{"detail": "..."}`.

| Status | When                                                                                          |
| ------ | --------------------------------------------------------------------------------------------- |
| `422`  | Invalid `scan_type`, missing/empty `target`, or a target that is malformed for its `scan_type`. Validation errors from the request body use FastAPI's standard list-style `detail`. Invalid targets never reach VirusTotal. |
| `404`  | VirusTotal has no record of the target (unknown hash or IP).                                  |
| `429`  | VirusTotal rate limit or quota reached. Includes a `Retry-After: 60` header.                  |
| `502`  | VirusTotal rejected the server's API key, was unreachable, or returned an unexpected response. |
| `504`  | A newly submitted URL analysis did not finish in time (about 60 seconds).                     |

**Behavior notes**

- **New URLs are submitted and polled.** If VirusTotal has never seen a URL, the
  API submits it and polls for the result with backoff. This is noticeably
  slower (often 10-20 seconds) than a lookup of an already-known URL
  (about 1 second).
- **Caching.** Results are cached in memory for `CACHE_TTL_SECONDS`, keyed by
  the exact `(scan_type, target)` pair. A repeat request within the TTL returns
  the same result with `cached: true` and makes no VirusTotal call. Errors are
  never cached. The cache is per process and is cleared on restart.
- **Rate limits.** The VirusTotal free tier allows 4 requests/minute and 500/day.
  Submit-and-poll uses several requests per new URL.
- **CORS** currently allows all origins (`*`). Restrict this to the extension's
  origin before deploying (see the TODO in `main.py`).

## Monitoring at `/monitor`

Monitoring is mounted in the same FastAPI process when the database and 2FA
administrator settings described above are configured. The root `/scan` route
still returns its original response. With monitoring enabled, successful
VirusTotal verdicts from `/scan` are also recorded in monitoring risk and scan
history. Failed lookups that reached VirusTotal appear as Unknown events. With
monitoring enabled, `/scan` requires an approved scanning account session or a
trusted server-side ingestion token. Managers cannot submit scans. User checks
are linked to personal ownership. These bridge requests do not trigger external email or webhook
notifications. Protected ingestion is the path for device and extension events.

The monitoring dashboard shows the overview, devices, extensions, findings,
risk levels, scan history, alerts, security events, exceptions, and monthly
reports. Its backend routes use the `/monitor/api/` prefix. The first password
step (`POST /monitor/api/admin/login`) issues a short-lived challenge; a valid
authenticator code (`POST /monitor/api/admin/verify`) issues a bearer session.
The backend requires this session on every administrator route, and sign-out
revokes it. Repeated invalid codes trigger a temporary lockout.

| Purpose | Routes | Access |
| --- | --- | --- |
| Event ingestion | `POST /monitor/api/scans` | Trusted caller with `X-Ingest-Token` |
| Downloaded-file hash check | `POST /monitor/api/downloads/scan` | Trusted caller with `X-Ingest-Token` |
| Downloaded-file upload and hash check | `POST /monitor/api/downloads/scan-file` | Trusted caller with `X-Ingest-Token` |
| Dashboard data | `/monitor/api/overview`, `/devices`, `/extensions`, `/scans`, `/findings`, `/alerts`, `/events` | Administrator bearer session |
| Risk policy and evidence | `GET /monitor/api/risk-policy`, `GET /monitor/api/scans/{scan_id}` | Administrator bearer session |
| Administrator file checks | `POST /monitor/api/admin/downloads/scan`, `POST /monitor/api/admin/downloads/scan-file` | Administrator bearer session |
| Alert review | `POST /monitor/api/alerts/{alert_id}/status` | Administrator bearer session |
| URL/domain exceptions | `GET/POST /monitor/api/overrides`, `POST /monitor/api/overrides/{id}/deactivate`, `GET /monitor/api/overrides/audit` | Administrator bearer session |
| Reports | `GET /monitor/api/reports/monthly/stats`, `GET /monitor/api/reports/monthly`, `POST /monitor/api/reports/monthly/generate`, `POST /monitor/api/reports/monthly/{YYYY-MM}/send` | Administrator bearer session |

For example, a trusted caller can submit a synthetic check from PowerShell:

```powershell
$scan = @{
  device_id = 'lab-device-1'
  device_name = 'Lab laptop'
  target_kind = 'url'
  target = 'https://example.invalid/sample'
  signals = @(@{ code = 'suspicious_url'; status = 'detected' })
} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/monitor/api/scans' `
  -Headers @{ 'X-Ingest-Token' = $env:INGEST_TOKEN } `
  -ContentType 'application/json' -Body $scan
```

This sample is for API setup and is not a real threat verdict.

The risk engine owns the scoring weights on the server. Only detected signals
add points; unknown checks never count as clear. Scores of 0–29 are Low,
30–59 Medium, 60–79 High, and 80–100 Critical. A scan with no assessable
checks is Unknown, with no numeric score. Every result also reports whether
the assessment was complete, partial, or unknown. High and Critical findings
create alerts and threat events.

Administrator exceptions match an exact URL or hostname, require a reason,
expire within 90 days, and keep an audit trail. A matching exception retains
the original risk score and findings while suppressing the external alert
notification. Only the URL fingerprint and hostname are stored for URL scans;
the full visited URL is not retained.

The downloaded-file routes use SHA-256. The hash route accepts a digest; the
multipart route accepts a file of up to 32 MB, hashes it, and discards the
bytes. Only the hash is sent to VirusTotal. Missing keys, unknown hashes,
rate limits, and lookup failures produce an **Unknown** result. The backend
does not automatically see browser downloads: a future trusted Chrome
extension or companion service must call one of these routes. Do not put
`INGEST_TOKEN` or `VT_API_KEY` in a distributed extension.

Monthly reports cover a completed UTC calendar month. Administrators can view
aggregate statistics, generate a saved draft, and explicitly email it. Set
`LLM_PROVIDER=ollama` and `OLLAMA_MODEL=qwen3:4b-instruct` for this computer's local
model; **Start ExtSecure.cmd** starts the installed local runtime and API after
a restart. OpenAI remains an optional provider with its backend key and model. The
model receives only aggregate counts and fixed finding categories, never raw
URLs, filenames, device names, or individual events. To prepare and send the
previous completed month from a trusted scheduler, run:

```bash
python -m alba_security.monthly_runner
```

Use `--prepare-only` to save without emailing. The runner reads process
environment variables, so supply `DATABASE_URL`, the OpenAI settings, and
SMTP settings to its process; it does not automatically read `.env`. No
schedule is installed by this repository.

Report retries retain recipient hashes for accepted SMTP handoffs and retry only
remaining recipients. SMTP acceptance does not confirm inbox delivery. Run one
report worker for SQLite; PostgreSQL serializes dispatch with a row lock. A crash
between external acceptance and the database commit can still cause a resend.

For report email and High/Critical alert email, configure `SMTP_HOST`,
`SMTP_PORT`, `SMTP_FROM`, `ADMIN_EMAILS`, and any SMTP login credentials. SMTP
uses TLS. High/Critical alerts can also go to an HTTPS
`ALERT_WEBHOOK_URL` or comma-separated `ALERT_WEBHOOK_URLS`; an optional
`ALERT_WEBHOOK_SECRET` signs each payload. Failed or unconfigured deliveries
are recorded as failed or skipped, not as successful sends. The example
settings contain no working credentials or recipient addresses.

Webhook requests include a stable `Idempotency-Key` for each alert. Receivers
must implement deduplication using that key. Alert status changes do not resend
notifications. Review requests accept `status` (`open`, `acknowledged`, or
`resolved`), a reason of 8–500 characters, and an optional `expected_status`.
The dashboard supplies the displayed status to reject stale updates. Suppressed
alerts remain part of exception history and cannot be reopened manually.

Password and authenticator endpoints share a limit of 20 attempts per client
per 60 seconds, using the connection peer and a bounded in-memory store. This
limit is per process; use a trusted ingress for a shared deployment-wide limit.

For deployment, keep the API and dashboard behind HTTPS and suitable network
controls, restrict CORS, and rate-limit sign-in at the ingress. The standalone
`/scan` compatibility service remains public only when monitoring is disabled.
When monitoring is enabled, it requires an approved session or a trusted machine
token. Use a trusted server-side integration for monitoring ingestion;
do not expose its token to untrusted clients.

## Testing

The test suite uses mocked VirusTotal, LLM, email, and webhook integrations and
temporary databases, so it makes no real external requests or deliveries:

```bash
pip install -r requirements-dev.txt
pytest
```

`tests/conftest.py` sets a dummy `VT_API_KEY` for the original API tests. The
Alba tests are under `tests/alba/`; they use SQLite for local verification.
Run the integrated app against a real PostgreSQL instance before deployment.

### Continuous integration

`.github/workflows/tests.yml` runs `pytest` on Python 3.14 (ubuntu-latest) for
every push and pull request to `main`. It sets no service secrets.

## Project Structure

```
extsecure-integrated/
├── .github/workflows/tests.yml   # CI: run pytest on push / PR to main
├── app/
│   ├── config.py                 # Settings (VT_API_KEY, CACHE_TTL_SECONDS)
│   └── services/
│       ├── cache.py              # In-memory TTL cache
│       └── virustotal.py         # Async VirusTotal v3 client + verdict logic
├── src/alba_security/            # Risk, monitoring API, reports, alerts, auth
├── dashboard.py                  # Streamlit administrator dashboard
├── docs/                         # Project documentation
├── tests/                        # ExtSecure and Alba pytest suites
│   ├── conftest.py
│   ├── helpers.py
│   ├── test_config.py
│   ├── test_main.py
│   ├── services/
│   └── alba/                     # Monitoring and integration tests
├── .env.example                  # Settings template; .env stays git-ignored
├── .gitattributes
├── .gitignore
├── main.py                       # FastAPI app, /scan, mounted /monitor
├── pyproject.toml                # Editable alba_security package metadata
├── pytest.ini
├── requirements.txt              # Runtime dependencies and editable package
├── requirements-dev.txt          # Adds pytest + respx
└── README.md
```


Chrome device enrollment, enabled-extension inventory and device block controls are now available in the MV3 console. See [extension setup and inventory workflow](extension/README.md#basic-device-and-chrome-setup-074) for registration, optional Chrome permissions, access enforcement and limitations.


## Core scope (0.8.13)

Optional workflow automation, policy-change approval, control-effectiveness analytics, advanced database monitoring, domain importing and migration checksum comparison have been removed. See [current project scope](docs/Project%20Scope.md).

Incident investigation, persistent High/Critical containment, scanning, access approval, accounts and 2FA, reports, privacy, detection evaluation, usability testing and safe exports remain available. See [incident response and containment](docs/Incident%20Response%20and%20Threat%20Containment.md).

Reload the unpacked Chrome extension after updating its files. Migration 0004 removes the six optional-feature tables. It preserves security evidence, incidents, threat blocks and the administrative audit trail.
