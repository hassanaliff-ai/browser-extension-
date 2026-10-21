# SecureScope API Contract — Extension ↔ Backend

Status: draft. The RDAP and scan endpoints are implemented. Manual checks in
the development extension call the scan endpoint on loopback; automatic visits
and page links remain local. No live VirusTotal key is configured. The scan
endpoint returns HTTP 503 while reputation evidence is unavailable, rather
than a Low verdict. Offline tests inject mock evidence.

## Endpoint

```
POST http://127.0.0.1:8001/api/v1/check
```

`background.js` fixes this development address. The backend must set
`SECURESCOPE_ALLOWED_EXTENSION_ID` to the unpacked SecureScope extension ID
before Chrome may call it. Only that extension's cross-origin manual check is
allowed. Run the standalone SecureScope API on port 8001 for local development;
the separate TestAPI on port 8765 is not used by this extension.

## Request (sent by the extension)

```json
{
  "url": "https://example.com",
  "source": "manual",
  "checked_at": 1758431000000
}
```

- The request model accepts `"visited"` and `"manual"`, but this development
  extension sends only user-initiated `"manual"` checks. Visits stay local.
- `checked_at` is milliseconds since epoch (`Date.now()` on the client).
- `url` is a site origin only: scheme, hostname and optional port. It contains
  no username, password, path, query or fragment. This policy applies to every
  automatically observed site, not just search engines. It limits URL-specific
  phishing detection and must be documented in the final UI.

## Response (expected from the backend)

```json
{
  "origin": "https://example.com",
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
- The required `origin` echo must exactly match the origin sent in the request.
- The extension rejects more than 10 reasons, non-text or empty reasons, or a
  reason longer than 200 characters before a backend verdict can affect a scan.
- `cached` is informational (lets the UI optionally show "cached result").

This standalone loopback prototype has no account login or administrator
operations. The combined ExtSecure backend already uses password and
authenticator verification before issuing administrator sessions. When
SecureScope gains administrator operations in the combined application, those
routes must use that existing session and role check rather than a second
account store. The extension's allowed Chrome origin is a development CORS
restriction, not user authentication. The final contract also needs a
data-retention policy and client presentation of RDAP evidence. A lookup
failure must never be represented as `Low` risk merely because no threat
result was returned.

## Shared ExtSecure scan integration

The combined app's authenticated `POST /extension/scan` uses its existing
VirusTotal lookup and scan database. It also calls SecureScope's RDAP module
with only the registered domain. The response adds `domain_age` with either
`{"status":"Known","age_days":12}` or `{"status":"Unknown"}`; it never
returns a page path or RDAP server URL. A known age below 30 days records the
existing `new_domain` risk signal, while an unavailable age records that signal
as Unknown. ExtSecure shows the age next to the scan result. This shared path
uses the existing account session and does not call the standalone SecureScope
reputation prototype, which has no configured live provider. Its RDAP wait is
bounded to 2.5 seconds and a timeout remains Unknown.

## How the extension uses this

- The extension ALSO runs its own local heuristics
  (`scoreUrlLocally` in `background.js`) before calling the backend.
- The two verdicts are merged: whichever reports the higher severity wins,
  and reasons from both are combined.
- If the backend doesn't respond within 3 seconds, errors, returns a
  malformed response, or returns a non-200 status, the extension keeps its
  local warning signs and marks backend evidence unavailable. A low local
  score does not certify safety.

## Error handling (backend side)

The loopback API allows 30 scans and 10 direct RDAP requests per minute in this
process. HTTP 429 includes `Retry-After` in seconds. Any non-200 response is treated as "unavailable" by the extension — no
need to match a specific error schema, though a `{"error": "..."}` body is
fine for your own debugging.
