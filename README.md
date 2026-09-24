# SecureScope Backend

FastAPI backend for SecureScope, a browser extension that checks URLs (and file
hashes / IP addresses) for malicious content using the
[VirusTotal](https://www.virustotal.com) v3 API.

## Setup

1. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt          # runtime only
   pip install -r requirements-dev.txt      # runtime + test tools (pytest, respx)
   ```

3. Configure environment variables. Copy `.env.example` to `.env` and fill it in:

   | Variable            | Required | Default | Description                                           |
   | ------------------- | -------- | ------- | ----------------------------------------------------- |
   | `VT_API_KEY`        | yes      | -       | Your VirusTotal API key (64 hex characters).          |
   | `CACHE_TTL_SECONDS` | no       | `600`   | How long scan results are cached, in seconds.         |

   The app **refuses to start** if `VT_API_KEY` is missing or empty, and exits
   with an error pointing at `.env.example`.

## Run

Start the development server with auto-reload:

```bash
uvicorn main:app --reload
```

The API will be available at http://localhost:8000.

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

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

## Testing

The test suite is fully mocked (using [respx](https://lundberg.github.io/respx/)),
so it makes no real VirusTotal calls and needs no API key:

```bash
pip install -r requirements-dev.txt
pytest
```

`tests/conftest.py` sets a dummy `VT_API_KEY` automatically.

### Continuous integration

`.github/workflows/tests.yml` runs `pytest` on Python 3.14 (ubuntu-latest) for
every push and pull request to `main`. It sets no secrets.

## Project Structure

```
securescope-backend/
├── .github/workflows/tests.yml   # CI: run pytest on push / PR to main
├── app/
│   ├── config.py                 # Settings (VT_API_KEY, CACHE_TTL_SECONDS)
│   └── services/
│       ├── cache.py              # In-memory TTL cache
│       └── virustotal.py         # Async VirusTotal v3 client + verdict logic
├── docs/                         # Project documentation
├── tests/                        # pytest suite (mirrors app/)
│   ├── conftest.py
│   ├── helpers.py
│   ├── test_config.py
│   ├── test_main.py
│   └── services/
├── .env.example                  # Template for your local .env (git-ignored)
├── .gitattributes
├── .gitignore
├── main.py                       # FastAPI app, /scan endpoint, error mapping
├── pytest.ini
├── requirements.txt              # Runtime dependencies (pinned)
├── requirements-dev.txt          # Adds pytest + respx
└── README.md
```
