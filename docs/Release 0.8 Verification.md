# ExtSecure 0.8.0 — practical verification

Verified on 7 October 2026. This update improves Hasan's extension interfaces,
risk presentation, access review, privacy controls and reporting workflows.
The existing API and database architecture are used without a schema change.

## Changes

- Refined the console, toolbar popup and blocked-page styling. Added role-specific
  quick actions, clear API connection states and recovery instructions in Settings.
- Fixed narrow-screen navigation overflow; preserved horizontal scrolling inside
  evidence tables. Improved keyboard focus, control sizes, text contrast and RTL
  risk-number ordering. These checks do not constitute accessibility certification.
- Kept popup risk results compact, with a link to the full evidence workspace.
  Scan evidence can be downloaded as JSON using the existing authorized result.
- Search now announces matching-record counts, explains its scope and shows an
  empty-result message without changing stored evidence.
- Account review initially assigns the requested role within the reviewer's
  allowed role list. Changing the person resets identity confirmation and reason.
- Changing a website request resets destination confirmation and reason. Reject
  hides/disables duration; approve restores it. Rejection omits duration from the
  submitted form. Existing backend review confirmation remains mandatory.
- File and website results explain completed checks, missing reports, cached
  results, provider errors and retry delays. Unknown stays distinct from Low.
  Unknown distribution bars now use a neutral colour.
- Weekly report inputs are validated as completed Monday-based UTC periods;
  monthly inputs require completed calendar months. AI setup errors include the
  local-model configuration used by this project.
- Optional page/text-file explanation requests require explicit consent before
  file contents are read. File buffers are cleared even if hashing fails.
- Protected successful responses are rejected if the originating sign-in has
  changed. AI polling remains bound to that sign-in. Malformed successful JSON
  and request timeouts give recovery errors without creating a safe verdict.
- Browser settings, local file pages and URLs containing credentials cannot
  enable the popup website scan action.

## Results

| Verification | Result | Scope |
| --- | --- | --- |
| Existing backend suite | 694 passed, plus 16 subtests | Isolated test data; provider and delivery mocks |
| Extension suite | 170 passed | Shipped modules, worker messages, UI handlers, role controls and new regressions |
| Rendered layout scenarios | 10 passed | Real headless Chrome with synthetic UI fixtures; desktop, mobile, popup, sign-in, 2FA and Arabic |
| Actual local API | HTTP 200 | `http://127.0.0.1:8765/health` identified ExtSecure API |
| Actual local AI runtime | HTTP 200 | Installed `qwen3:4b-instruct` found through local model inventory |

The 10 layout scenarios cover the overview, Unknown file result, website access,
account review, a 390-pixel dashboard, Arabic website access, the 400-pixel popup
and the Arabic popup, plus sign-in and separate authenticator verification. Each checks page overflow and keyboard focus. Both website
access scenarios check the actual duration helper in a real DOM, including
disabled-field omission from FormData. Screenshots use test records, not live data.

The API and local model were stopped when checked. The existing launcher started
them successfully; no credentials were reset. The release installer checks hashes,
preserves `.env`, and saves the previous changed extension files for recovery.

## Responsibility coverage

| Hasan's responsibility | Verification evidence |
| --- | --- |
| Risk logic and UI | Fixed-rule scoring, Unknown/partial handling, rendered result screens |
| Administrator dashboard | Role-specific navigation and quick actions, responsive overview |
| Security-event logging | Existing scan and event audit tests; evidence export |
| Administrator 2FA | Existing authentication, expiry, replay, rate-limit and role tests |
| Whitelist and overrides | Existing expiry/revocation/confirmation/hierarchy tests; reject/approve UI checks |
| Downloaded-file scanning | Hash/privacy tests and clear/not-found/provider-error result checks |
| Weekly/monthly reports and ML | Existing report, period, AI-job and ML tests; new input validation |
| High-severity alerts | Existing notification, delivery-failure and status/audit tests |
| Usability and accessibility | Keyboard, RTL and viewport checks; existing observation workflows |
| Privacy and governance | Existing retention/access tests; new pre-read content-consent enforcement |
| Incident response and cases | Existing scan linkage, assignment, notes, revision and resolution tests |
| Detection quality | Existing labelled-scenario, false-positive, missed-threat and Unknown evaluation tests |
| Security guidance | Risk explanations, API recovery steps and role-specific next actions |
| Policy change management | Existing draft, independent review, activation and historical-policy tests |

## Practical limits and final checks

Reload the installed extension at `chrome://extensions`, close old console tabs
and open ExtSecure again. Complete authenticator verification yourself if asked.

Native Chrome navigation enforcement with real account approvals still requires
the installation smoke checks in `extension/README.md`; layout fixtures do not
verify that enforcement. VirusTotal hash reputation cannot establish the safety
of an unlisted file. Email/webhook delivery needs configured recipients and
credentials; no real messages were sent during this verification. ML analysis
needs sufficient historical activity. Individual HTTP requests now stop after
25 seconds; an unusually slow first-time URL lookup may need history review and
a later retry. Existing asynchronous AI jobs use short polling requests.

## Implementation references

- [Chrome extension service-worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
  documents the fetch-response timeout that informed the bounded request handling.
- [W3C: target size](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html)
  informed control sizing and spacing.
- [W3C: status messages](https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html)
  informed error announcements and filter-result feedback.
