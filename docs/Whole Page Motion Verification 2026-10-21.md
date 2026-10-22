# Whole page motion

ExtSecure 0.8.43 — 21 October 2026.

Navigation now moves the complete main page, including its title, introduction, cards, tables and panels. The sidebar and toolbar remain stable. Movement runs for 420 ms with a 36 px directional slide; Arabic reverses the direction. Initial page entry uses an 18 px vertical movement. Background refresh of the same section does not replay navigation movement.

Theme switching also animates the existing page with an 8 px lift and a small scale change from .985 to 1. Its contents are not replaced, preserving unfinished input. Opacity remains at least 97 percent for section movement and 99 percent for theme movement. Completed animations retain no transform. The workspace clips horizontal motion to prevent viewport overflow, without clipping native top-layer review dialogs.

The saved animation setting and operating-system reduced-motion preference cancel active movement immediately. The blocked-page warning remains visible. No security request waits for an animation.

Verification: 277 JavaScript tests passed, including the new theme-page animation test. All 24 real Chromium interface checks and 14 add/remove/restore dialog checks passed using isolated profiles with synthetic API/account records. These cover whole-main-page native movement, RTL, completion cleanup, cancellation, settings preservation, narrow layout, forced colours, critical blocked-page messaging, dialog confirmations and keyboard focus.

The source, public installation ZIP and existing workspace extension folder are updated. Reload an already-running unpacked copy once at chrome://extensions. No database or manifest permissions changed.
