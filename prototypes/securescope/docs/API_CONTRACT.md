# SecureScope API Contract — Extension ↔ Backend

Owned jointly by: Extension Lead & Backend & API Lead
Status: draft. Step 13 includes the RDAP evidence endpoint and the
`/api/v1/check` scan endpoint. The backend's VirusTotal adapter has no live
API key, and network requests from the extension remain disabled in
`background.js` until an approved reputation source and security controls
are in place. The scan endpoint returns HTTP 503 while reputation is
unavailable, rather than a Low verdict. Offline tests inject mock evidence.

## Endpoint

```
POST {BACKEND_BASE_URL}/api/v1/check
```

`BACKEND_BASE_URL` is set in `background.js` (currently `http://localhost:8000`
for local dev). Update it — and the matching `host_permissions` entry in
`manifest.json` — once the backend has a real deployed URL.

## Request (sent by the extension)

```json
{
  "url": "https://example.com",
  "source": "visited",
  "checked_at": 1758431000000
}
```

- `source` is either `"visited"` (detected automatically) or `"manual"`
  (user pasted a link to check).
- `checked_at` is milliseconds since epoch (`Date.now()` on the client).
- `url` is a site origin only: scheme, hostname and optional port. It contains
  no username, password, path, query or fragment. This policy applies to every
  automatically observed site, not just search engines. It limits URL-specific
  phishing detection and must be documented in the final UI.

## Response (expected from the backend)

```json
{
  "severity": "High",
  "reasons": ["Flagged as phishing by 4 VirusTotal engines"],
  "lookup_status": "partial",
  "cached": false
}
```

- `severity` MUST be exactly one of: `"Low"`, `"Medium"`, `"High"`,
  `"Critical"` (case-sensitive) — the extension and popup share one
  severity → colour mapping and don't normalize casing.
- `reasons` is always an array, even when empty (`[]` if nothing flagged).
- `lookup_status` is required and is `"complete"` or `"partial"`. A backend
  error or unavailable result is not a Low verdict; the extension falls back
  to its local-only result. The team must approve the final coverage wording.
- An optional `origin` echo must exactly match the origin sent in the request.
- The extension rejects more than 10 reasons, non-text or empty reasons, or a
  reason longer than 200 characters before a backend verdict can affect a scan.
- `cached` is informational (lets the UI optionally show "cached result").

The final contract still needs authentication, RDAP evidence,
and a data-retention policy. A lookup failure must never be represented as
`Low` risk merely because no threat result was returned.

## How the extension uses this

- The extension ALSO runs its own local heuristics
  (`scoreUrlLocally` in `background.js`) before calling the backend.
- The two verdicts are merged: whichever reports the higher severity wins,
  and reasons from both are combined.
- If the backend doesn't respond within 3 seconds, errors, returns a
  malformed response, or returns a
  non-200 status, the extension falls back to the local-only verdict and
  logs `backend unreachable` — it never blocks or breaks on a flaky
  backend.

## Error handling (backend side)

Any non-200 response is treated as "unavailable" by the extension — no
need to match a specific error schema, though a `{"error": "..."}` body is
fine for your own debugging.
