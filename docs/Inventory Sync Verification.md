# Complete Chrome inventory — version 0.8.35

## Cause and scope

The live check found Basel's approved device registered with only ExtSecure recorded and no full-inventory sync timestamp. Registration records the connecting extension; it does not prove that Chrome management permission has been granted or that a complete snapshot has been uploaded. The server was not truncating the device's extension list.

Inventory covers extensions visible to Chrome's management API in the connected profile, including disabled extensions. Other Chrome profiles and browsers need separate connections. It does not enumerate arbitrary programs installed on the computer.

## Implemented changes

- Show incomplete inventory explicitly in the device card and selected-device view, with the permission step needed to complete it.
- Synchronize on extension installation, removal, enablement and disablement, on worker startup and through a one-minute alarm while Chrome is running.
- Permit an approved paired device to synchronize its own inventory after account sign-out. The narrow device credential cannot read account data or write another device's snapshot. Blocked, revoked, removed and pending devices remain rejected.
- Preserve enabled and disabled entries, mark absent entries uninstalled, and avoid repeated audit entries for unchanged snapshots.
- Report installed, enabled and disabled counts after synchronization.

## Basel's update steps

1. Download the current `ExtSecure Chrome Extension.zip`. Close ExtSecure tabs and extract the update into the same existing unpacked-extension folder; keep its path unchanged. No reinstall or clearing browser data is necessary.
2. Open `chrome://extensions`, click Reload on ExtSecure and confirm version 0.8.35.
3. In that same Chrome profile, open ExtSecure → My account → Connect Chrome extensions and allow Chrome's requested inventory permission. If the profile is not paired, complete Add this device and approval first.
4. Check the completed sync timestamp/count. An administrator can select Basel's device name in Inventory → Extensions to see its inventory. Disabled extensions are included; uninstalled history remains behind its existing toggle.

This host cannot remotely grant Chrome permissions or replace an unpacked extension on Basel's computer. His live inventory will change after those steps complete successfully.

## Verification

- Backend inventory, presence and remote-control regression: 75 tests passed.
- Device-inventory checks on disposable PostgreSQL: 7 tests passed.
- JavaScript suite: 250 tests passed.
- Real Chromium Manifest V3 exercise: 7 checks passed, including an enabled fixture, a disabled fixture, the selected-device UI and a genuine disable event updating backend inventory after account sign-out. No account session was restored.
- Test fixture devices and accounts were isolated from Basel's live account and inventory.

## Automatic updates on another computer

GitHub stores the updated source and ZIP; Chrome does not automatically update an unpacked extension from GitHub. For ordinary Chrome-managed automatic updates, publish ExtSecure as the same Chrome Web Store item, install that store version on the other computer, and publish subsequent packages with increasing manifest versions. Store publication/review has not been performed by this change. An organization-managed enterprise deployment is a separate alternative.

The current ZIP uses the temporary public API. A recreated tunnel requires a rebuilt package with the new address. A stable HTTPS API address is needed before dependable long-term distribution.

Official references:

- https://developer.chrome.com/docs/extensions/reference/api/permissions
- https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world
- https://developer.chrome.com/docs/webstore/update
