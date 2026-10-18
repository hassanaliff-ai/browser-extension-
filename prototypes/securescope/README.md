# SecureScope prototype by Basel Mohammed Alhawi

This folder contains Basel's SecureScope proof of concept: a Manifest V3 Chrome
extension, local URL and on-page link checks, an RDAP domain-age module, a local
FastAPI service, an offline-tested VirusTotal adapter, and tests. It is kept
separate from the root `extension/` and backend because those belong to the
existing ExtSecure application and use different contracts and access controls.

## What works in this prototype

- The service worker observes completed top-level HTTP(S) visits. The popup can
  check a pasted address, and a content script labels locally suspicious links.
- Stored history contains site origins only, up to 50 for no more than seven
  days. Credentials, paths, queries, and fragments are removed before storage.
- The inline checker handles links added or changed after page load and caps
  work at 2,000 anchors and 500 unique site origins per page.
- The RDAP module derives registration-age evidence via registry routing. The
  FastAPI service exposes local RDAP and scan endpoints.
- The VirusTotal adapter uses mock reports in tests. No API key is included.
  Without an approved reputation source, the scan endpoint returns 503 rather
  than treating missing evidence as a safe result.
- Loopback development addresses are excluded from public-site risk scoring.

The extension's backend switch is **off**. The database, administrator
authentication, and integration into the root ExtSecure application are outside
this prototype. Do not run both Chrome extensions in the same test profile:
ExtSecure can block navigation while SecureScope observes it.

## Run the tests

From this folder, run the JavaScript tests with Node.js:

```powershell
node --test
```

Create a Python environment, install the backend dependencies, and run the
offline Python tests:

```powershell
python -m venv .venv
& '.\.venv\Scripts\python.exe' -m pip install -r requirements-backend.txt
& '.\.venv\Scripts\python.exe' -m unittest discover -s test -p 'test_*.py'
```

To inspect the local API documentation, start the service on loopback only:

```powershell
& '.\.venv\Scripts\python.exe' -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/docs` and stop the service with Ctrl+C when
finished. The local API has no administrator authentication or request rate
limit, so it must not be exposed to a network or used with Alba browsing data.
The `/docs` page serves its Swagger UI 5.33.3 CSS and JavaScript from
`backend/static` instead of a CDN. These files come from `swagger-ui-dist`;
its Apache 2.0 licence is included as `backend/static/LICENSE`.

## Load the extension for manual testing

In a separate, signed-out Chrome profile, open `chrome://extensions`, enable
Developer mode, choose **Load unpacked**, and select this folder's
`securescope-extension` directory. The extension version is 0.9.1. On a page
with a known URL-shortener link, the local checker may show a Medium label;
do not open the destination to test the label. Ordinary unlabeled links are
not certified safe.

The draft extension/backend contract is in [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md).
The message contract is in [`docs/MESSAGING.md`](docs/MESSAGING.md). Before
connecting this prototype to the main application, agree on risk-result and
authentication contracts, permissions, and the data-retention policy.
