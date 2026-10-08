# ExtSecure 0.8.1: simplified extension design

The native Chrome popup now starts with the current destination and one primary
scan action. File check and Dashboard are secondary actions. The previous slogan,
large dark hero and repeated status text were removed. Account, settings and
sign out are grouped under **Account & settings**. Website access and API
connection diagnostics remain directly accessible.

Risk severity, score, recommended action, confirmed threat findings, unavailable
checks, provider errors, applicable exceptions and Unknown warnings stay visible.
**Scan details** opens the target, policy version, scan reference, successful
provider metadata and JSON evidence download. The full evidence workspace remains
available. Cosmetic simplification does not change risk scores or approval rules.

The dashboard uses flat cards, smaller navigation, three compact shortcuts,
charts and recent events. A concise alert review strip appears only when alerts
need attention. Repeated guidance cards were removed. English, Arabic, keyboard
focus, reduced motion and narrow layouts remain supported. Language and time
preferences on the sign-in screen open on demand.

## Verification

- **172 extension tests passed.** These exercise existing URL privacy, file
  hashing, role limits, approval duration, account review, authentication state,
  inventory, AI reporting and worker message contracts. Two additional UI tests
  verify that high-severity findings and Unknown/provider-failure guidance remain
  outside optional details.
- **13 isolated headless Chrome layout scenarios passed.** These cover the
  dashboard, mobile dashboard, file lookup failure, website approvals, Arabic
  approvals, account review, English and Arabic risk popups, the initial popup,
  high-severity and Unknown popups, sign-in and authenticator verification.
- No horizontal document overflow was found at the tested viewport sizes.
  Keyboard focus works. Scan details reveals evidence export; Account & settings
  reveals settings and sign out. Rejecting website access hides and disables
  duration, excludes it from form data, and approving restores it.
- The ZIP is checked for CRC errors, matching source hashes and Manifest V3
  configuration. Runtime scripts and styles are bundled; extension CSP continues
  to prohibit inline scripts.

The layout checks use synthetic data and isolated browser contexts. They do not
authenticate a real account, visit a malicious site, send notifications or verify
live provider results. Backend and database code were not changed or retested
for this visual update. Previous functional evidence is recorded separately in
`Release 0.8 Verification.md`.

## Installation

The installer backs up changed files from the prior installed version before
copying the update into `C:\Users\hassa\browser-extension-`. It compares the
private `.env` hash before and after installation without exposing its contents.
The updated ZIP is also copied to that folder.

Reload ExtSecure in `chrome://extensions`, then close old console tabs and reopen
the extension. Chrome should show version **0.8.1**. Reload is required to replace
the running worker and cached extension pages.
