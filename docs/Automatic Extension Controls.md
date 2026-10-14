# Automatic extension controls — 0.8.27

Inventory → Extensions lets an authorized higher approver turn an extension on, turn it off, or block it without asking the device user to approve the decision.

| Approver | Devices they can control |
| --- | --- |
| Head administrator | All account levels, including their own |
| Administrator | Normal users, managers, and their own device |
| Manager | Normal users and their own device |
| Normal user | No administrative extension controls |

Peer accounts and higher account levels are denied in the backend. An unknown device owner requires the head administrator. Managers cannot request uninstallation. The operator must confirm the target and provide a reason; the recipient has no ExtSecure approval step.

The approved device's scoped connection credential delivers pending commands even after the account signs out. It grants access only to that device's directives and receipts, never dashboard or account data. Removed, pending, rejected and revoked connections are denied. An already-approved blocked device retains the control channel for containment.

Connected workers wait on a 20-second long poll. In the current single-worker deployment, new decisions wake the waiting request within its 200 ms check interval, followed by network and Chrome processing. Offline devices remain pending. Chrome alarms restart delivery after worker interruptions. Multiple API workers fall back to the next poll; wakeups are not shared across processes.

Block disables the extension and re-enforces the block when Chrome reports it enabled again. On/Off/Block use Chrome's actual management API. A verified result is recorded with its decision revision; stale receipts cannot acknowledge a newer decision. Receipts update the observed enabled state and preserve an audit trail.

Each device must load this version, be approved and have the existing Chrome management permission. Reload the unpacked extension at chrome://extensions. Other-device installations use the rebuilt ExtSecure Chrome Extension.zip.

Chrome can require a native gesture or confirmation for enabling an extension and can protect organization-managed extensions. Those restrictions produce a visible failure, not fabricated success. Uninstallation still requires Chrome's native confirmation. See [Chrome management API](https://developer.chrome.com/docs/extensions/reference/api/management#method-setEnabled).

## Validation

Verified on 14 October 2026: 100 backend regression tests, 33 checks against a disposable PostgreSQL database, 237 JavaScript tests and 22 Chromium checks passed. The live TestAPI deployment and rebuilt package were checked separately. Existing real scan records remain intact.

The regression suite covers all 16 actor/owner role combinations, peer administrator denial, signed-out device delivery, receipt revisions, cross-device isolation, revoked credentials, pending enrollment, and approved blocked-device containment. JavaScript checks cover scoped transport, signed-out execution and native restriction handling.

The separate Chromium test uses a harmless unpacked extension and a synthetic backend with QA-only management permission pregrant. It verifies real On/Off/Block, signed-out execution, manual re-enable containment, device selection and retained inventory history. It does not manipulate the user's installed extensions or claim to test every Chrome policy environment.
