# ExtSecure Chrome extension 0.6.0

Version 0.6 adds evidence-based AI explanation forms to URL/file risk results
and weekly/monthly report snapshots within the Monthly reports panel. The
backend keeps the LLM key, verifies optional file hashes and exact page scope,
and enforces the existing account privileges. Content sharing starts unchecked.
Generated prose is a review draft and never changes severity or grants access.
See `AI_INTEGRATION.md` at the project root for model configuration, privacy
scope, API paths and the repeatable weekly/monthly preparation command.

The primary interface is a Manifest V3 extension: a toolbar popup, extension-owned
console and blocked-page screen. Its service worker talks to the existing FastAPI
backend. These pages run at `chrome-extension://`; Streamlit is not required.

## Install or update

1. Start the configured backend at `http://127.0.0.1:8765`.
2. In Chrome, open `chrome://extensions` and enable Developer mode.
3. Choose **Load unpacked** and select `C:\Users\hassa\browser-extension-\extension`.
   If ExtSecure is already loaded, choose its **Reload** button instead.
4. Chrome needs navigation and HTTP/HTTPS host access for the blocking feature.
   Keep that requested access enabled for sites you want ExtSecure to control.
5. Pin the extension and sign in with an approved account and authenticator code.
6. Choose **Settings** for English/Arabic and UTC, KSA or another supported zone.
   Arabic uses a right-to-left layout; URLs, hashes and verification codes stay LTR.

The ZIP contains the extension, without server secrets, accounts or the database.
Extract it before using Load unpacked. The installed backend keeps its existing
`.env`, protected account setup and database outside this folder.

## Website approval

HTTP and HTTPS top-level website navigation redirects to the local blocked screen
before the network request, using a packaged `declarativeNetRequest` rule. This
works while the service worker is asleep. The configured backend origin on port
8765 is exempt; extension/browser pages are outside this HTTP/HTTPS gate. The
gate starts immediately when the extension and its required site access are enabled.

An approved, signed-in account requests access with a business reason. The site
stays blocked. A Manager, Administrator or Head of Administrator records a reason
and chooses a decision:

- **Approve one visit:** requester-specific, expires after ten minutes and is
  consumed atomically by the backend when **Open approved website** is selected.
- **Approve URL whitelist:** reusable by all approved accounts, with an expiry
  of 1–90 days (30 by default). Whitelisted visits automatically continue after
  the blocked screen validates current permission against the backend.
- **Reject:** keeps the destination blocked.

The requester cannot review their own request, including the main administrator.
Normal users see only their own requests and cannot review/revoke permissions.
Managers can review website access without gaining unrelated governance powers.
Renewing an exact URL whitelist supersedes earlier grants. Revoking a current
entry also closes any older active grants for that same URL, including records
created by an earlier version.
Pending requests expire after fourteen days; requests are limited to twenty per
account per hour. A duplicate pending request returns the existing record.

Approval matches one scheme, hostname, port and path. It does not approve all
paths or subdomains. Query parameters and fragments are deliberately excluded
from the approval scope and stored request. A redirect to a different URL needs
that URL's approval. Managers/administrators can revoke whitelist entries. Checks
and decisions are audited. Website approval does not lower risk scores or suppress
alerts; the older security exceptions remain a separate notification workflow.

For an opened visit, Chrome receives an exact-URL, GET-only, tab-scoped session
rule. It is removed after navigation commits, errors, tab closure, sign-out or a
thirty-second timeout. Whitelist visits are revalidated on each navigation;
permanent browser allow rules are not cached. Offline, expired and revoked
sessions cannot create a new navigation permission.
An expired or revoked session clears existing temporary permissions. Changing
the destination or signing out during approval cancels the pending opening.

This controls new top-level visits while the extension is enabled. Already loaded
pages and embedded resources are outside the new-visit gate. It is not an OS or
enterprise network control against removing the extension. Native Chrome cache,
history and service-worker behavior still need the smoke checks below.

## Language, time and privacy

Saved language/time-zone settings use `chrome.storage.local`; tokens stay in
trusted-context, memory-only `chrome.storage.session`. Activity timestamps use
the chosen IANA zone and its DST rules. Saudi Arabia uses `Asia/Riyadh`. Monthly
statistics keep UTC calendar boundaries. Evidence and notes keep their original
language; controls and core journeys are translated.

Permissions: storage, activeTab, declarativeNetRequest, webNavigation and alarms
plus HTTP/HTTPS host access for redirects. The extension does not inject content
scripts, read file URLs, automatically read downloads or declare external message
handlers. Its CSP allows API connections only to the configured local backend.
Scripts, styles, icons and QR enrollment are local; no CDN is used.

The original blocked destination is held temporarily in trusted browser session
storage so opening it preserves query parameters. It is cleared after an allowed
navigation, tab closure, sign-out or thirty minutes. Only explicit access requests
send the cleaned scheme/host/port/path and reason to the backend. Approval history
is retained for audit; expiry ends access without deleting the decision history.
The privacy inventory documents this separate data category.

Reputation scanning remains explicit. URL scans default to origin only; optional
paths exclude query/fragment/credentials. Files up to 32 MiB are SHA-256 hashed
locally and only the digest is sent. VirusTotal, LLM, email and webhook credentials
stay on the backend. Registration needs owner approval and TOTP verification.

## Verification

Run `node --test tests/*.test.js` from this folder. Backend approval tests are in
`tests/alba/test_website_access.py`; the full report is
`../docs/Extension Verification.md`. Chrome API mocks test message grants,
navigation-rule scope and cleanup; they do not prove native Chrome installation.

The port-8911 HTML preview is clearly labelled and uses isolated fixtures on port
8767. It cannot enforce Chrome navigation or substitute for loading the extension.
This session cannot install into native Chrome. After loading/reloading it, check:

1. Unapproved HTTP/HTTPS URLs show ExtSecure's blocked screen before loading.
2. Request access, review it through a different Manager/Administrator account,
   then open the approved visit in the original tab.
3. Reload: the one-visit permission must no longer apply.
4. Approve a whitelist URL, revisit, revoke it and revisit again.
5. Sign out, stop the backend or expire approval: the next visit stays blocked.
6. Check a second tab, different path/host/scheme/port and a server redirect.
7. Restart Chrome, test cached/history navigation and suspend the worker; the
   packaged gate remains enabled and stale visit permissions must not persist.
8. Check English/Arabic, KSA/UTC, the toolbar popup and authenticator verification.

The reporting/ML, incident, governance, file, alert and account workflows remain
connected. Live LLM drafts and notifications require backend configuration. ML
needs sufficient real history and supports investigation rather than proving a threat.
