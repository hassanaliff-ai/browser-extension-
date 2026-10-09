# ExtSecure Chrome extension 0.8.8

The console and popup use teal navigation bars with warm terracotta accents. Choose Light, Dark or
Use device setting in Settings, then Save preferences. The console header also
has a Dark mode toggle. Appearance is stored locally with language and time
zone; no backend setting or permission is added. The saved choice also applies
to sign-in and the blocked-page screen. System mode follows the device theme;
explicit light/dark choices remain fixed. Warning panels use warm rose and rust
tones, with labelled risk levels retained. See
`../docs/Release 0.8.3 Appearance Verification.md` for test evidence.

Version 0.6 adds evidence-based AI explanation forms to URL/file risk results
and weekly/monthly report snapshots within the Reports panel. The
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
6. Choose **Settings** for Light/Dark/device appearance, English/Arabic and UTC, KSA or another supported zone.
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

- **24 hours / 7 days:** requester-specific reusable permission until expiry.
  Visits continue after the blocked page validates permission. Once expired,
  the requester must submit a new request.
- **Forever (whitelist):** reusable by all approved accounts, with no expiry.
  Approval remains valid until an authorized reviewer revokes the URL.
- **Reject:** keeps the destination blocked.

Managers review normal-user requests; administrators review manager requests;
the head reviews administrator requests. Higher roles may also review lower
roles. Only the head can approve or reject their own website requests.
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
stay on the backend. Registration needs higher-role approval and TOTP verification.

## Verification

Run `node --test tests/*.test.js` from this folder. Backend approval tests are in
`tests/alba/test_website_access.py`; the full report is
`../docs/Extension Verification.md`. Chrome API mocks test message grants,
navigation-rule scope and cleanup; they do not prove native Chrome installation.

The port-8911 HTML preview is clearly labelled and uses isolated fixtures on port
8767. It cannot enforce Chrome navigation or substitute for loading the extension.
After loading/reloading the installed extension, check:

1. Unapproved HTTP/HTTPS URLs show ExtSecure's blocked screen before loading.
2. Request access, review it through a different Manager/Administrator account,
   then open the approved visit in the original tab.
3. Reload during temporary approval: access remains valid. After expiry, request again.
4. Approve a whitelist URL, revisit, revoke it and revisit again.
5. Sign out, stop the backend or expire approval: the next visit stays blocked.
6. Check a second tab, different path/host/scheme/port and a server redirect.
7. Restart Chrome, test cached/history navigation and suspend the worker; the
   packaged gate remains enabled and stale visit permissions must not persist.
8. Check English/Arabic, KSA/UTC, the toolbar popup and authenticator verification.

The reporting/ML, incident, governance, file, alert and account workflows remain
connected. Live LLM drafts and notifications require backend configuration. ML
needs sufficient real history and supports investigation rather than proving a threat.

Version 0.6.4 stores permanent grants using the reserved timestamp 9999-01-01
in existing non-null expiry columns. API responses use `permanent: true` and
`expires_at: null`; this needs no database schema migration. Old one-visit
records keep their original scope; the extension now offers reusable durations.

Permanent website grants are shown in both Website access and Whitelist &
overrides. Both views read the same backend records and use the same revocation
endpoint. Website allowlisting grants browsing access; it does not create an
alert-suppression exception or reduce risk results.

Every website approval and rejection requires checking the destination/business
need confirmation. The API requires a strict boolean `confirmed: true`, rejects
missing/false or non-boolean values without modifying the request, and records
successful confirmation in the decision audit.


### Basic device and Chrome setup (0.7.4)

Signed-in sessions expire 24 hours after successful authenticator verification. The extension uses the backend-issued expiry; activity does not extend the deadline. Sessions issued before this setting changed keep their original expiry; sign out and sign in once to receive the new duration.

1. Reload ExtSecure on Chrome's extensions page and sign in to an approved account.
2. Open **Inventory → Devices** or **My account**, choose **Trusted device** or **Blocked device** under **Device access before adding**, then click **Add this device**. The choice is required in the UI, worker and backend for new registrations. **Trusted device** connects immediately for an administrator or head; managers and normal users still require administrator approval. **Blocked device** registers the profile with activity denied from creation, regardless of account role. An administrator can later allow it through **Manage device access**. ExtSecure's own inventory record is saved, but other extensions are not synced while blocked. Name and IP address are optional under **Optional device details**; the operating system is detected automatically.
3. For a **Trusted device** selection, head-administrator and administrator devices connect immediately. Manager and normal-user devices appear as **Pending approval**. An administrator opens **Devices → Manage device access**, selects the device, chooses **Allow device**, enters a decision reason and saves. A pending user clicks **Check approval status** to continue; permitted inventory sync resumes after approval. A **Blocked device** selection remains blocked until an administrator explicitly allows it. Refreshing an existing connection never changes its access status.
4. Click **Connect enabled Chrome extensions** and accept Chrome's optional permission prompt to include other enabled extensions. A declined or failed prompt keeps the device connected and shows an error with retry instructions. Use **Refresh devices & extensions** for an immediate refresh. Once permission is granted, inventory also refreshes after extension changes, at sign-in and every 30 minutes while signed in.
5. To add another computer, load ExtSecure and click **Add this device on that computer**. The computer must reach the configured backend. The default 127.0.0.1 API address reaches only its own local machine; a remote deployment needs a reachable secured API origin configured in the extension and its CSP.

After installing an update, close existing console tabs and reopen the console from the Chrome extension icon. A console left open during reload can lose its worker connection. Check that Chrome shows **ExtSecure 0.8.11** loaded from `C:\Users\hassa\browser-extension-\extension`. A website preview cannot register Chrome devices or enumerate extensions.

**Unknown extension action** means the running worker does not recognize the requested message; that action did not reach the API. The console now checks the running worker's version and inventory capabilities. If they do not match this package, it replaces device connection actions with **Restart ExtSecure**. That button invokes Chrome's runtime reload directly, so it works even when the old worker lacks inventory message handlers. Close the old tab, reopen through the extension icon and sign in after restarting. Saved device identities and backend records are preserved. If Chrome still shows an older version, use **Load unpacked** with the exact folder above and disable the other old copy; do not load the ZIP or its parent folder.

**Manage device access** offers **Allow device** and **Block device**. Allow approves a pending device or unblocks a blocked device. Block rejects a pending request or blocks an active device. Only administrators and the head can approve, block or unblock devices. Managers and normal users can request their current device and edit its optional metadata after approval. Blocked or rejected devices stay blocked on reconnect; reconnecting never silently approves or unblocks them. **Pending approval** and **Blocked devices** filters show the relevant queues.

The browser generates a random connection key once and keeps it in Chrome local storage restricted to trusted extension contexts. The backend stores only its hash. The key is saved before registration, so retries after a lost response reuse the same device identity. Repeated clicks do not create duplicate devices. A successful device connection survives inventory failure and the UI offers an explicit retry. Account sessions remain in memory-only extension storage and every account uses 2FA. Adding the first managed device activates mandatory enrollment for business operations. Administrator inventory controls, sign-in, My account and logout remain available for recovery.

IP is descriptive metadata, not a credential. An optional entered IP is labelled **Entered IP**. When the API sees a non-loopback connection peer, that address is labelled **Connection IP**; it may be shared through NAT. Localhost and unknown connection peers are displayed as **Not provided**, never presented as a computer's LAN address. Chrome does not reliably expose a physical computer's LAN IP in this flow. Name and operating system describe the linked Chrome profile, not an independently attested hardware identity.

Only enabled extension IDs, names and versions are collected through `chrome.management.getAll()`. Inventory does not inspect extension source, permissions, page content or browsing history. Older scan placeholders appear under **Older scan records**. Disabled or removed extensions remain as **Not in latest snapshot**, preserving scan history. Last-sync times disclose stale information. Inventory metadata is not a malware verdict.

**Existing device connection (advanced)** and **Advanced connection recovery** preserve the older one-time-code workflow for an already registered device; codes are not required for normal setup. Codes expire after 30 minutes. Re-pairing revokes the previous browser credential.

Blocking prevents new ExtSecure scans, inventory sync, dashboard business operations and approved website visits from the linked profile. Existing loaded pages are not removed. This is an ExtSecure service and navigation control, not an operating-system firewall or an enterprise guarantee against uninstalling/disabling the extension. Clearing browser data loses the connection key; a normal user or manager must request and obtain approval again. Browser keys and pairing codes are excluded from inventory lists and audit logs.


### Account profile logos

Every approved account type can open **My account → Profile logo**, select a PNG, JPG or WebP image of up to 2 MiB, then choose **Save logo**. Images are cropped to a square and re-encoded as a 192-pixel PNG before saving. The original file and its metadata are not retained or sent to the API. **Remove logo** restores the username initials. The saved logo appears in the console sidebar and popup account details.

Logos are stored locally in this Chrome profile, separately for each authenticated username. They survive sign-out and extension reload, but do not sync to other devices. Uploads require an active, backend-verified account; caller-supplied usernames cannot select another account's storage. No additional Chrome permissions are requested.


### Security event device and user attribution

**Security events** displays the device name and ID, the verified scanning user, and the privacy-safe website or file-hash reference. A separate Actor column retains the person who performed a later decision. New website and file scan events snapshot the device name and scanning account; renaming a device does not change that historical name. Older events resolve the device and account from their linked scan history when possible. Machine ingestion and records without verified account ownership show **Not recorded**, rather than inventing a user. URL visibility follows privacy governance; private URL parameters and original file names are not added to the event log.

These records describe ExtSecure checks. The extension does not read or execute downloaded files automatically or claim to monitor files opened outside Chrome. The user initiates a file hash check through the extension.


### Adjustable table size

Use the **Table size** selector above any populated table, or open **Settings**, to choose **Compact**, **Standard**, or **Spacious**. Compact reduces row spacing and text size; Spacious increases them. Standard preserves the previous layout. The setting applies to all console tables and is stored locally in this Chrome profile. It persists after reload and preserves appearance, language and time-zone choices. Changing the size does not reload scan data, reset table search, or hide any rows or columns; wide tables remain horizontally scrollable.

Table sizes save directly in Chrome local storage, persist after reopening, and update other open console tabs. Compact, Standard and Spacious change row spacing without hiding records. This remains compatible with an older running background worker.

Workflow automation (Investigate) provides incident assignment rules, reviewer notifications and overdue-case escalation. Control effectiveness (Govern) provides time-window metrics and evidence assessments for blocking, approvals, exceptions and alerts. Administrators configure rules and record assessments; managers view metrics and their own workflow notifications. The API must run for deadline checks. After installing 0.8.8, reload ExtSecure in chrome://extensions and reopen the console. See ../README.md for metric definitions and limits.

### Reproducible real-browser tests

The browser smoke runner loads this actual Manifest V3 package and its service
worker into a separate Playwright Chromium profile. It does not attach to your
personal Chrome, borrow its session, or replace Chrome APIs with mocks. This
provides a test route when desktop browser-control tools cannot inspect an
extension URL. It does not modify those tools or disable their URL checks.

Install test-only dependencies from this directory, with TestAPI already running:

```powershell
npm install
npx playwright install chromium --no-shell
npm test
npm run test:browser
```

The default browser command checks anonymous startup and API connectivity without
registering a device or scanning a destination. For the full live test, run from
the installed project root using its Python environment:

```powershell
python scripts/test_extension_browser.py --live
```

The launcher prompts for the existing head-administrator username, masked
password and masked current authenticator code after the test browser is ready.
No credentials are passed in command-line arguments, embedded in the test, or
printed. Both authentication steps go through the shipped UI and real backend.
Live mode captures read-only database snapshots before and after, registers a
clearly named QA browser, checks example.com and locally hashes a generated
harmless text file. It verifies console views, blocking and navigation evidence,
table sizing and sign-out. Test records remain for inspection; existing records
are not deleted. Only the test browser's session is signed out.

Artifacts, database hashes, differences and screenshots stay under
`.private/extension-smoke/`. The database comparison reports row counts and hash
changes; it does not export account secrets. Tests do not explicitly generate or
deliver reports. A novel file hash may correctly return Unknown when VirusTotal
has no report. See [verified results](../docs/Extension%20Browser%20Verification.md).

The launcher follows [Playwright's extension-testing workflow](https://playwright.dev/docs/chrome-extensions)
using its supported Chromium channel and a persistent test context. The browser
download is for testing, not a replacement for your regular Chrome installation.
