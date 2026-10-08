# Workflow and control compatibility fix — 8 October 2026

Extension: 0.8.9. API: 0.4.1 (unchanged).

## Problem and evidence

The reported message occurs in the Chrome worker's route guard, before HTTP. Using the historical 0.8.7 core from the repository, both `GET /api/workflow/rules` and `GET /api/controls/effectiveness?days=30` reproduced the guard rejection. Both routes are allowed in the current core. The running API's health check succeeded, and its monitoring OpenAPI schema contained both task route groups. This establishes a reproducible older-worker cause; the user's live Chrome worker was not directly inspected because this session had no Chrome control surface.

## Change

- Worker STATE advertises version, operations contract 1, and workflow/control capabilities.
- Both task pages check compatibility before issuing requests.
- Recovery displays the worker and console versions and an explicit Chrome runtime restart button, with English and Arabic text.
- Valid requests rejected by an older worker and disconnected extension contexts receive actionable recovery. Invalid requests and backend permission failures keep their original denial.
- No new permissions, API credentials, database changes, auth bypasses or arbitrary URL grants.

## Validation

- **206/206 Node tests passed**, including 10 added tests for compatibility, actual worker dispatch, denial and explicit restart.
- The actual background message listener forwarded **14 supported route/method combinations** to the fixed authenticated monitoring API, retaining the method, bearer header and JSON body.
- Five invalid route/method combinations were rejected without a network request.
- Isolated Chrome UI checks passed: rule creation, reviewer acknowledgement, case navigation, assessment reference filtering and submission, reporting period switching, and manager scoping.
- **Eight layout checks** passed across the two task sections, English/Arabic, light/dark, and desktop/mobile sizes.
- **Two older-worker browser recovery checks** passed: no task API request was sent, no automatic reload occurred, and clicking the button invoked Chrome runtime reload once.
- The isolated browser used synthetic accounts and records. These tests did not create incidents or assessments in the user's production data.

## Activation and limits

Updated files must be loaded by Chrome. Reload the unpacked ExtSecure extension on `chrome://extensions`, close old console tabs, and reopen it from the extension icon. A newly loaded recovery panel can perform the reload through **Restart ExtSecure**. Sign in again if required. Live activation in the user's existing Chrome session remains unverified; a healthy API does not prove that Chrome has loaded the new worker.
