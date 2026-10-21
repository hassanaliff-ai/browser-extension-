# Modern action workflows — 21 October 2026

ExtSecure 0.8.41 extends the visual refresh to actual add, manage, remove and review interactions.

## Changed

- Shared form disclosures now open native modal review dialogs. Read-only details remain native expandable sections. Dialogs retain their original forms and fields inside the originating record rather than cloning them or changing their API requests.
- Device registration uses labelled Trusted/Blocked choice cards with no preselected trust level.
- Device and extension removal show the exact selected target, consequences, required reason and fresh confirmation. Restore has a separate treatment and accurate wording.
- Extension management shares one Actions column. Management review includes the extension and device, distinguishing uninstall from inventory-only removal.
- Incident removal and affected-device protection include target identity and consequences inside the dialog.
- Cancel/Close/Escape do not submit pending forms; labelled automatic motion preferences retain their immediate-save behavior. Confirmation and initial trust selections are cleared, focus returns to the trigger, and keyboard focus cycles within the review. Browser modifier shortcuts are left alone.
- Pending mutations disable dismiss controls; server errors remain inline. Required constraints still prevent submission; browser validation balloons are replaced with labelled inline feedback.
- Periodic inventory refresh pauses during open reviews or visible edits. Closed draft forms no longer pause status refresh indefinitely.
- The existing device restore endpoint is exposed in the removed-device history. No backend privilege, blocking behavior, database schema or permission is changed.

## Verification

- 270 JavaScript regression tests passed, including the existing worker, inventory, role, validation and incident contracts.
- 14 native Chrome action-dialog checks passed with synthetic inventory: required trust choices, cancel, fresh confirmation, keyboard focus, Escape, dark/motion-off updates, narrow screens, server conflicts, Arabic, exact removal payload and restore review.
- 16 shared motion/theme/Arabic/responsive Chrome checks passed.
- 14 native Chrome containment/incident safety checks passed, including confirmed incident removal while retaining threat rules.
- 22 native Chrome inventory management checks passed, including enable, disable, block, protected entries, extension/device removal and retained history.
- Screenshots reviewed for add and remove dialogs, desktop/light, narrow/dark and Arabic. Synthetic test profiles and provider responses are not production security evidence.

A single reload is required after updating an unpacked extension. The public ZIP contains the current public API address and no private credentials. These focused checks do not certify every accessibility scenario or simulate all operating-system/browser policies.
