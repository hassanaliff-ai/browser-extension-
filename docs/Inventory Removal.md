# Inventory removal — 0.8.19

Administrators and the head administrator can remove any extension record in **Inventory → Extensions**, including ExtSecure and older scan records. Expand **Remove from inventory**, enter a reason and confirm the selected record. This archives the inventory entry; it does not uninstall software from Chrome. The separate **Manage extension** controls continue to support Chrome uninstall where permitted.

Use **Show removed or uninstalled extensions** to review archived entries. An extension can be restored while its device remains active. Chrome synchronization does not silently restore an archived entry.

In **Inventory → Devices**, use the row's **Remove** form to disconnect a device. Removal revokes every browser credential and pairing code, blocks the device and archives its associated extensions in one transaction. A removed device cannot submit new scans, reconnect with an old token or receive extension controls. Removing the current profile clears its local connection and temporary navigation grants. Enroll it again as a new device when access is needed.

The **Removed devices** filter preserves visibility of archived devices. Scans, findings, incidents, threat blocks and audit records remain available. Inventory removal never releases blocked threats. Manager and normal-user accounts cannot remove inventory records.

Changes require the current record revision, preventing stale or repeated submissions. Migration `0006_inventory_removal.sql` adds inventory state and revision columns without deleting existing records.

Validation: 57 backend tests and 230 extension tests passed. The isolated database run passed 13 tests, including five checks against PostgreSQL and eight role checks against SQLite. Sixteen real Chromium extension checks passed, covering device selection, management controls, removal, history and ExtSecure remaining installed after inventory removal. Real-browser removal checks use a disposable fixture; no actual user device was removed during verification.
