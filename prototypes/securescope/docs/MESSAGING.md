# SecureScope Extension — Integration Points

How to plug your piece into `background.js` (Extension Lead) without
editing it directly. The current integration points are:

## 1. Alerts & UI Lead → `alerts.js`

`background.js` calls `notifyIfRisky(entry)` from `alerts.js` every time a
site is scored (visited or manually checked). Implement your
notification/badge logic inside that one function — don't need to touch
`background.js` at all.

```js
export async function notifyIfRisky(entry) { ... }
```

Use `browserAPI` from `./browser-shim.js` instead of `chrome.*` directly,
so the extension stays cross-browser (Firefox stretch goal).

## 2. Alerts & UI Lead → popup reads `chrome.storage.local`

Key: `"visitHistory"` → array of entries, newest first, capped at 50. Entries
older than seven days are pruned when a new result is saved, when the worker
starts, and by a scheduled alarm while Chrome is running. The popup hides any
expired entries immediately. Version 0.4.1 cleared older full-URL history once
as a privacy migration.

```js
{
  url: string,          // site origin only, no path/query/fragment/credentials
  source: "visited" | "manual",
  tabId: number | null,
  severity: "Low" | "Medium" | "High" | "Critical" | "Unknown",
  reasons: string[],    // empty array if nothing flagged
  lookupStatus: "local-only" | "complete" | "partial", // absent for unsupported URL
  checkedAt: number,    // ms since epoch
}
```

Read example (works in the popup too):

```js
const { visitHistory = [] } = await browserAPI.storage.local.get("visitHistory");
```

## 3. Popup → manual URL check

To check a URL the user pastes into the popup, send a runtime message —
don't call any scoring functions directly from popup.js:

```js
const entry = await browserAPI.runtime.sendMessage({
  type: "SECURESCOPE_CHECK_URL",
  url: userTypedUrl,
});
// entry has the same shape as the storage schema above (source: "manual")
```

In this build, this runs local heuristics and attempts a backend check for
manual requests only. The popup displays the combined result and explicitly
marks backend evidence unavailable when that check cannot complete.

## 4. Backend & API Lead

See `API_CONTRACT.md` in this folder for the request/response shape.
`BACKEND_BASE_URL` in `background.js` points at the standalone SecureScope API
on `http://127.0.0.1:8001/`. The matching `host_permissions` entry is in
`manifest.json`. Automatic visits and inline page links stay local.

## 5. Inline page links

`inline-links.js` is a content script on HTTP and HTTPS pages. It sends only
unique site origins, in batches of at most 50, using:

```js
{ type: "SECURESCOPE_CHECK_LINK_ORIGINS", origins: ["https://example.com"] }
```

The worker accepts this message only from a top-level tab content script and
returns `{ results: [{ origin, severity, reasons }], lookupStatus: "local-only" }`.
These checks are local-only and are not added to `visitHistory`. The content
script labels Medium, High and Critical destinations; no label does not mean
a link is safe. At most 500 distinct origins are assessed per page.

## Firefox stretch goal

`browser-shim.js` exports `browserAPI`, which resolves to the native
`browser` global on Firefox or `chrome` on Chrome. Use `browserAPI.*`
everywhere instead of `chrome.*` directly. `manifest.json` already has a
`browser_specific_settings.gecko` block for Firefox. To test: open
`about:debugging#/runtime/this-firefox` in Firefox → "Load Temporary
Add-on" → select `manifest.json` inside the extension folder.
