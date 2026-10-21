# Modern UI and motion — 21 October 2026

ExtSecure extension version 0.8.40.

## Result

The console now uses refined teal navigation, clearer active sections, consistent card shapes, restrained shadows, cleaner table framing, stronger focus indicators and responsive spacing. Popup and blocked pages share the presentation layer. Existing warm action colors and separate risk-severity colors remain.

The interface adds 200 ms section-entry effects, short theme color transitions and subtle hover/switch/chevron feedback. Animations use local CSS and a small native JavaScript module; there are no external assets, libraries or extra browser permissions. Security processing never waits for presentation effects. Entry effects start at 94% opacity so evidence is never hidden, and completed effects do not retain a transformed container.

## User control and accessibility

- Settings has a labelled native checkbox exposed as an accessible switch: **Interface animations**.
- Changes save immediately to Chrome profile preferences, survive reload and synchronize with other open extension pages.
- Device reduced-motion preference takes priority and updates without reopening the extension.
- Off disables all CSS animation/transition effects, including existing spinners; status text continues to describe pending work.
- Keyboard Space toggles the switch, with a visible focus indicator. Arabic labels and RTL layout are supported.
- Theme toggles preserve unfinished settings and forms. The saved appearance selector updates without refetching the active view.

Preferences remain local presentation settings. This release changes no database schema, approval permissions, risk scores, report schedules, email scope or threat-block rules. Reload an unpacked extension once after updating its files.

## Verification

- 265 JavaScript tests passed; none failed or skipped. Includes existing worker, inventory, authentication, containment, settings and UI checks plus motion-specific validation.
- 16 real Chromium checks passed with synthetic account/API evidence and real Chrome preference storage. Covered actual background-color transitions, switch naming, form preservation, immediate off, reload persistence, cross-window sync, live reduced-motion changes, keyboard use, Arabic RTL, narrow layout, popup rendering and visible critical blocked-page messaging.
- 14 additional real Chrome containment checks passed using isolated synthetic evidence and native Chrome request-blocking rules.
- Screenshots reviewed at desktop and narrow widths in light/dark/Arabic layouts. Screenshots and test profiles stay private and are not production activity evidence.

These are focused interface and safety-regression checks. They do not claim a complete accessibility certification or test new external security-provider behavior. Backend functionality was not modified beyond release metadata.
