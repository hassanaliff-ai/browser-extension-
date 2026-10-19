# Fresh account and device joining — 19 October 2026

At the project owner's explicit request, the existing basel account was deleted from PostgreSQL. No basel2 account or pending enrollment existed. Authentication sessions, login challenges, registration enrollments, legacy invitations and authenticator replay/lock state for these exact names were cleared. Basel's former device keys were removed, its registration blocked and pairing code cleared. Historical scans and audit records were preserved. An account_deleted audit record documents the operation. Neither name is configured as an additional server account.

## Join from another computer

1. Install the current ExtSecure Chrome Extension.zip using the included public API address. For an existing unpacked install, replace files in the same folder and Reload at chrome://extensions.
2. Register once, complete the authenticator step and wait for account approval. The head administrator sees the verified account in Accounts → Pending registrations. Approval is still required.
3. Log in, open My account, select Trusted device and click Add this device. No manually entered IP address is required. Normal-user and manager devices appear in Inventory → Devices as Pending approval. Administrators can approve them there. Account approval and device approval are separate controls.
4. Click Connect Chrome extensions and grant Chrome's permission to upload the installed-extension list. The head administrator selects the device name in Inventory → Extensions to see that profile's extensions.

All supported account roles may submit their own device. Different computers/Chrome profiles receive separate device entries. Approval and blocking are enforced by the backend. Dashboard tables refresh every 15 seconds when visible and no review form is being edited. A running Chrome profile sends heartbeats; registration alone does not falsely mark a computer Active.

The public API health check returned 200 after the reset. The API host and temporary tunnel must remain online; this test deployment is not permanent internet hosting. Another computer must have network access to that HTTPS endpoint. These checks cannot grant Chrome permission or install files remotely on another person's device.

## Verification

Basic inventory tests cover every role's connection, head-administrator dashboard visibility, ExtSecure inventory entry, real-heartbeat presence, separate Windows/macOS/Linux enrollment requests, pending approval, successful approval and sync, blocked-device enforcement, retries and revoked keys. Older assertions were updated to distinguish connection presence from access state; no fake Active status was introduced.

Result: all 31 basic inventory and device-joining tests passed. No test accounts or test devices were added to the live database.
