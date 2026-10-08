# ExtSecure Chrome extension 0.5.0 verification

Verified on 5 October 2026. The extension package and installed backend are updated
in `C:\Users\hassa\browser-extension-`. Existing credentials, `.env`, account setup
and production database were preserved. New access tables were added at startup.

## Results

| Check | Result | Evidence and scope |
|---|---|---|
| Full Python suite | 491 passed; 16 subtests passed | Temporary test databases and mocked external services. Final JUnit: `full-access-final-tests.xml`. |
| Extension JavaScript | 56 passed; zero failures | Chrome API mocks plus pure URL/rule/locale checks. `access-extension-tests.xml`. |
| Installed API and role retest | 46 passed | Extension API, all roles and website approvals, executed against the installed copy with fresh temporary databases. `installed-access-tests.xml`. |
| Installed JavaScript retest | 56 passed; zero failures | Same extension checks executed from the installed folder. `installed-access-extension-tests.xml`. |
| Live installed checks | Eight passed | Backend health, all six approval route paths, anonymous denial/no-store for five access operations, installed version and enabled static gate. `access-live-checks.json`. |
| Package/copy integrity | Passed | 19 runtime/documentation assets in the ZIP; 32 source/install files hash-verified, with final worker/test/report updates verified separately. No server keys or database in the ZIP. |
| UI review | Passed for reviewed journeys | English/Arabic switching, RTL, KSA/UTC selection, preference persistence, password/TOTP, request submission, query removal, approval queue and blocked-page layout. Synthetic local preview; no native Chrome navigation claim. |

There are **547 unique automated tests** in the full Python and extension suites,
plus sixteen Python subtests. Installed retests repeat selected tests; they are
not added to the unique total. Artifacts are in `.preview/extension-ui` in the
authoritative workspace.

The first backend run exposed SQLite's naive/aware timestamp comparison in ORM
update synchronization. Database-only atomic updates fixed it; all fifteen new
approval tests then passed. The first full run exposed four old dashboard/profile
navigation mismatches. A compatibility entry directs users to the extension's
approval console; all four and the complete suite passed on the final run.
An additional logout check verifies that authentication is cleared even if
Chrome's temporary-rule cleanup reports an error.

## Website approval coverage

- Anonymous requests, reviews, whitelist reads and permission consumption fail.
- Approved normal users see only their own requests and cannot approve/revoke.
- Managers, administrators and the owner can review another account's request.
  Every role, including the owner, is prevented from approving its own request.
- Pending, rejected and expired approvals cannot open a destination.
- One-visit approvals belong to the requester. Repeated and simultaneous consumers
  cannot reuse the backend grant; only one consumption audit record is committed.
- Whitelist entries are reusable by approved accounts, expire and can be revoked.
  Changing host, port, scheme or path does not match an approved URL.
- Duplicate pending requests reuse their record; twenty new requests per hour is
  the limit. Stale reviews cannot duplicate a whitelist decision.
- Queries/fragments are removed before storage. Non-HTTP(S), credential-bearing
  and invalid path inputs are rejected. Whitespace-only reasons are rejected.
- Changes and permission consumption have audit records. Access API responses
  use `Cache-Control: no-store`.

## Chrome enforcement logic

The manifest enables a bundled redirect rule for HTTP/HTTPS main-frame navigation,
using Chrome's [declarativeNetRequest API](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest).
It is a real MV3 implementation, with no website wrapper or remotely hosted code.
The backend's exact local origin is exempt. No permanent browser whitelist rules
are installed; reusable whitelist entries are revalidated against the backend.

The worker tests verify:

- Only trusted extension pages can send API messages. Blocked-target metadata and
  navigation actions require that page's actual top-level tab.
- Private query values do not leave the browser for an approval request; opening
  an approved visit preserves the original URL locally.
- No approval, an expired session or an offline backend cannot add an allow rule.
- The rule is anchored to the exact, case-sensitive URL path, one tab, main-frame
  GET requests and a defined priority. A second tab or different URL is outside it.
- Backend consumption happens before the rule is added and before navigation.
- Commit, error, tab closure, timeout, logout and startup clear temporary access.
  Blocked-target metadata has a thirty-minute browser-memory expiry.
- Logout still drops authentication if a Chrome cleanup call itself fails.

This is a new top-level navigation control while the extension and its required
site access are enabled. It does not lock down Chrome settings or previously
loaded pages, inspect embedded resources, or provide an OS/network firewall.
The short opening rule is bounded by navigation lifecycle/timeout; the backend
grant itself is consumed atomically. Native cached/history navigation, worker
suspension, real navigation-event ordering and permission prompts are outstanding
Chrome smoke checks, listed in `extension/README.md`.

## Language and time review

- English and Arabic controls, headings and core sign-in/approval journeys work.
- Arabic sets `lang=ar`, `dir=rtl`; the console navigation moves to the right.
- URL/hash/code fields retain LTR formatting. Evidence and administrator notes
  retain their original language rather than being silently translated.
- Nine supported display zones include UTC, KSA, UAE, Bahrain, London, Paris,
  New York, India and Japan. IANA zones supply daylight-saving behavior.
- KSA correctly moves a UTC timestamp forward three hours, including crossing a
  day/month boundary. Monthly statistics still use UTC calendar boundaries.
- Settings persist across reopening and are available before sign-in. Local
  settings store only validated language/time-zone fields, without tokens.

Screenshots: `arabic-ksa-settings-final.png` and `arabic-blocked-page-final.png`.
The UI test account and database were synthetic. The preview banner is explicit;
the preview cannot provide Chrome navigation enforcement.

## Remaining verification

Load or reload `C:\Users\hassa\browser-extension-\extension` in native Chrome.
This session's connected browser cannot install/run native Chrome extensions.
The shipped Chrome APIs have been mocked for automated tests, so native behavior
is not reported as tested. Use the README's checks for first-load blocking, one
visit then reload, whitelist/revoke, second tabs, redirects, expiry/offline,
cache/history navigation, browser restart and worker suspension.

The existing role, 2FA, risk, file, incident, policy, privacy, evaluation, monthly
ML/report and notification regressions passed. No real VirusTotal scan, LLM draft,
email or webhook was triggered by these tests. External reporting/delivery still
needs its existing backend configuration and ML needs sufficient real history.
Approval history is retained for audit; its expiry is an access cutoff rather
than automatic erasure. It is documented separately in the privacy inventory.
