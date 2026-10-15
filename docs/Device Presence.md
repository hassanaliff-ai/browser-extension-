# Device connection status — 0.8.29

Device inventory and the device picker under Extensions show connection status separately from access policy.

- **Active**: the paired extension checked in within the last 90 seconds.
- **Offline**: no recent verified check-in. Chrome may be closed, the device may be powered off or asleep, or its network/API connection may be unavailable.
- **Awaiting pairing**: a registered inventory entry has no live pairing credential.
- **Removed**: retained history, excluded from active inventory.

Access remains independently **Trusted**, **Blocked** or **Pending approval**. Receiving a heartbeat does not approve an account, unblock a device or grant access to scans and other users' data.

The worker sends a credential-scoped heartbeat every 30 seconds without requiring an account session or Chrome management permission. Verified administrative-control polls also count as contact, supporting existing 0.8.27+ installations. Device and Extensions views refresh every 15 seconds when visible and no form is being edited. Last contact is shown separately from inventory's Last sync.

Only the server's UTC time determines presence. Scanning history, administrative table reads and pairing alone do not establish an active connection. A credential cannot select another device in a heartbeat request. Revoked and removed connections cannot renew presence. A new nullable `device_registrations.last_heartbeat` column is added by migration 0009; no old records are backfilled as active.

A standard browser extension cannot directly observe another computer's power switch. Offline is therefore a connection observation, not a claim that the machine is certainly powered off. Chrome alarm delivery may also be delayed during sleep or suspension.

## Verification

81 backend regression tests passed, followed by 14 checks on a disposable PostgreSQL database covering presence, bounded inventory reads and migration rollback/reapply. All 240 JavaScript tests and 22 Chromium inventory/control checks passed. Presence tests cover expiry, future timestamps, pending and blocked devices, cross-device isolation, revoked credentials and removed inventory. Chromium control checks use a harmless extension and a synthetic backend; they do not establish hardware power state.

The live PostgreSQL upgrade created a private backup and preserved 16 scans, 16 security events, 5 devices, 8 extension records and 16 scan ownership records. A live API read showed the connected Hasan profile Active, Jawad's profile Offline, and historical removed records still Removed. No test devices were added or restored for this check.
