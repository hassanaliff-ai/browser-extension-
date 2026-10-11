# Extensions by device and Chrome controls

Version 0.8.18 adds a device selector and On, Off, Block and Remove controls to **Inventory → Extensions**. Select an added device to see its last reported installed extensions, including disabled extensions. Inventory covers the linked Chrome profile; it does not inspect unrelated browser profiles or software on the entire computer.

Head of Administrator and Administrator accounts can issue controls. Managers can inspect inventory but cannot change extension state. Normal users can apply already authorized pending actions on their own approved paired profile from **My account → Device & Chrome connection → Apply pending extension controls**. They cannot create or change administrator directives.

| Action | Behavior |
|---|---|
| Turn on | Clears a block directive and enables an installed extension on the target profile. |
| Turn off | Disables the current installation once. |
| Block | Disables the extension and re-applies the disable action after extension changes or the control poll if it is enabled again. |
| Remove from Chrome | Requests uninstall on the target profile. Chrome always displays its own confirmation when one extension uninstalls another. |

An administrator confirms the extension and device and supplies a reason. Local actions execute through `chrome.management` after the backend accepts the directive. Remote Off/Block actions are checked every minute while the target profile is signed in, approved, connected and has granted the existing optional management permission. Remote On/Remove waits for a deliberate **Apply pending extension controls** click on the target profile because Chrome may require a user gesture or native confirmation. A pending or failed action must not be interpreted as successful containment. An offline browser, signed-out/expired session or unavailable API cannot receive controls. This extension-level enforcement is not enterprise device management.

**Connect Chrome extensions** grants the optional management permission and syncs installed extensions. Full snapshots run after extension changes, at sign-in and every 30 minutes; a one-minute control poll writes a snapshot only when an action is applied or fails. The UI keeps actual last-reported Chrome state separate from administrator intent and acknowledgment. Chrome/organization restrictions and cancelled confirmation are shown as failures. ExtSecure protects its own connection and cannot disable or uninstall itself through this view. Extensions protected by Chrome or organization policy cannot be bypassed.

Removed installations disappear from the default list; **Show extensions no longer installed** displays their retained records. Scans, risk evidence and audit records are preserved. No hard deletion of incident or scan evidence is performed. Multiple devices use distinct extension records even when the Chrome extension ID matches.

The additive PostgreSQL migration `0005_extension_inventory_controls.sql` records observed enabled/control capabilities and audited device-scoped directives. Revision checks reject stale decisions and receipts; paired device credentials restrict retrieval/acknowledgments to the target profile. API input rejects unsupported actions, missing confirmation and malformed outcomes. Only minimal metadata is sent: IDs, names, versions, enabled state and control capabilities; extension permissions and descriptions are not collected.

Chrome API reference: https://developer.chrome.com/docs/extensions/reference/api/management.

Verification includes real Chrome enable/disable/block on a disposable harmless extension, device filtering, self protection, local application of pending actions and re-enabling detection. Native uninstall confirmation/cancellation is covered with API doubles, not a silent deletion of a user's installed extension. PostgreSQL migration tests use a disposable database. The live migration created a private backup and verified preservation of all 242 pre-upgrade application records across 36 tables.

Results: 229 extension unit tests, 45 affected backend checks, 6 PostgreSQL integration checks and 11 real Chrome checks passed. The running TestAPI was restarted and verified to expose all three new control routes, the added inventory fields and a healthy PostgreSQL connection.
