# ExtSecure 0.8.2: full extension console

The native `chrome-extension://` console now uses a light sidebar, collapsible
workflow groups, section search and a mobile menu. The current section stays
open and highlighted. Search covers only the account's authorized views, finds
English and Arabic labels, announces empty results and restores previous group
disclosures when cleared. It never adds routes or privileges.

Console tables, forms, status badges, headings and spacing share one consistent
style across monitoring, inventory, investigations, approvals and governance.
An existing class conflict between a loading panel and the pending status badge
was fixed; pending badges no longer stretch to 200 pixels tall.

Website access puts the review decision first for authorized reviewers, with
request submission alongside it. Required destination/business review confirmation
and decision reasons remain present. Reject still hides and disables duration.
Requests show a readable requester role, followed by history and the whitelist.

Reports separates weekly/monthly generation, snapshot history and monthly
analysis/delivery. The monthly workspace opens on demand and stays open when
refreshed or another month is selected. ML, saved draft review, delivery and
history remain available. Optional AI content inputs open under a disclosure;
content sharing still requires explicit consent before file contents are read.
Connected Chrome devices use a compact connection panel. Initial registration
still requires choosing Trusted or Blocked before submitting the device.

## Verification

- **178 extension tests passed.** This includes five navigation tests for route
  limits, search/disclosure restoration, Arabic search, empty results and mobile
  focus, plus an actual UI-handler test for monthly disclosure preservation.
  Existing approval, 2FA state, inventory, URL privacy, hashing, risk feedback and
  reporting checks also passed.
- **28 isolated headless Chrome layout scenarios passed.** Tested screens:
  overview; file lookup failure; website approvals; account review; Reports;
  Devices; Extensions; incident cases; policies; privacy; detection evaluation;
  usability records; settings; alerts; overrides; security guidance; popup states;
  sign-in and authenticator verification. Coverage includes mobile overview and
  reports, Arabic approvals/popup/reports and an expanded monthly workspace.
- The checks verify document width, keyboard focus, bounded status badge height,
  section search, mobile menu state, empty results, approval duration behavior,
  report frequency input switching and access to monthly ML/delivery controls.
  Popup details, warnings and account controls were checked for regressions.
- The final Arabic report paragraph received a targeted layout recheck after its
  translation was added. The full results remain recorded separately from that
  targeted check.
- The ZIP is verified against source hashes and checked for CRC errors. Manifest
  V3 and the existing extension CSP are retained. The console stylesheet and
  navigation module are local bundled assets.

These tests use synthetic data and isolated browser contexts. They do not sign in
to a real account, send notifications, connect a real device or test live threat
providers. Backend/database code and privileges were not changed. Previous
backend verification remains in `Release 0.8 Verification.md`.

## Installation

The installer backs up changed prior-version files in the installed project's
`.private/updates` directory. It copies the new extension assets, practical
verification notes and ZIP, then checks file hashes. The existing `.env` hash is
compared before/after without printing its contents.

Reload ExtSecure in `chrome://extensions`, close old console tabs, and reopen
**Dashboard** from the toolbar popup. Chrome should show **0.8.2**. Old tabs retain
their previous rendered interface until reopened.
