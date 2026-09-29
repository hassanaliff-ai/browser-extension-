# SecureScope integrated backend

One FastAPI process serves the original SecureScope VirusTotal lookup API and
the Alba risk and monitoring service. The existing `POST /scan` contract remains
at the root. When monitoring is configured, administrator and ingestion routes
are mounted at `/monitor`; a Streamlit dashboard reads those routes. This
repository is backend and dashboard code. It does not include a Chrome extension.

## Setup

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
   `sqlite:///./securescope.db` for a local trial. Create an administrator password
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

Liveness check. Returns `{"status": "ok", "service": "SecureScope API"}`.

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
history. Failed lookups that reached VirusTotal appear as Unknown events. Public
`/scan` requests do not trigger external email or webhook
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
| URL/domain exceptions | `GET/POST /monitor/api/overrides`, `POST /monitor/api/overrides/{id}/deactivate`, `GET /monitor/api/overrides/audit` | Administrator bearer session |
| Monthly reports | `GET /monitor/api/reports/monthly/stats`, `GET /monitor/api/reports/monthly`, `POST /monitor/api/reports/monthly/generate`, `POST /monitor/api/reports/monthly/{YYYY-MM}/send` | Administrator bearer session |

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
`OPENAI_API_KEY` and `OPENAI_MODEL` on the backend to generate the summary. The
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

For report email and High/Critical alert email, configure `SMTP_HOST`,
`SMTP_PORT`, `SMTP_FROM`, `ADMIN_EMAILS`, and any SMTP login credentials. SMTP
uses TLS. High/Critical alerts can also go to an HTTPS
`ALERT_WEBHOOK_URL` or comma-separated `ALERT_WEBHOOK_URLS`; an optional
`ALERT_WEBHOOK_SECRET` signs each payload. Failed or unconfigured deliveries
are recorded as failed or skipped, not as successful sends. The example
settings contain no working credentials or recipient addresses.

For deployment, keep the API and dashboard behind HTTPS and suitable network
controls, restrict CORS, and rate-limit sign-in at the ingress. The public
`/scan` lookup and authenticated `/monitor` routes have different trust
boundaries. Use a trusted server-side integration for monitoring ingestion;
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
securescope-integrated/
├── .github/workflows/tests.yml   # CI: run pytest on push / PR to main
├── app/
│   ├── config.py                 # Settings (VT_API_KEY, CACHE_TTL_SECONDS)
│   └── services/
│       ├── cache.py              # In-memory TTL cache
│       └── virustotal.py         # Async VirusTotal v3 client + verdict logic
├── src/alba_security/            # Risk, monitoring API, reports, alerts, auth
├── dashboard.py                  # Streamlit administrator dashboard
├── docs/                         # Project documentation
├── tests/                        # SecureScope and Alba pytest suites
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
