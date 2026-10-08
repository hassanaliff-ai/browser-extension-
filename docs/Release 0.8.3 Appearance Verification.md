# ExtSecure 0.8.3: dark mode and warm accents

Settings now offers **Light**, **Dark** and **Use device setting**. The console
header also has a **Dark mode** toggle whose pressed state follows the active
theme. Preferences are validated and saved in Chrome local storage alongside
language/time zone. Unknown credential fields are discarded; appearance is not
sent to the backend. Existing preferences without a theme default to Light.

Device mode follows later OS appearance changes. Explicit Light or Dark choices
override the device setting. The selected appearance applies when opening the
console, popup, sign-in and blocked-page screen. Appearance controls are placed
first in Settings and are also available before sign-in and on blocked pages.

Terracotta, soft rose and rust accents replace decorative yellow tones. Dark
surfaces use charcoal panels with light text and coral accents. Labelled risk
levels, Unknown guidance, confirmations, role access and scores keep their
existing meaning. Risk-result border colors remain visible in dark mode. The
high-risk chart line is dashed to distinguish it from total scan activity.

## Verification

- **181 extension tests passed**, including theme validation, legacy defaults,
  device appearance changes, explicit overrides and an actual UI-handler test
  that toggles appearance through the worker while preserving language/time.
  The worker test verifies a Dark preference is saved locally without a backend
  request or unrecognized private fields.
- **39 isolated headless Chrome scenarios passed.** These include the preceding
  console/popup layouts and dark overview, reports, approvals, devices, settings,
  file failure, Arabic reports, mobile overview, popup, sign-in and authenticator
  verification. The actual theme/localization functions are applied to rendered
  markup. Checks cover theme attributes, document width, keyboard access, badge
  size, navigation, approval duration and report controls.
- Four affected scenarios were rechecked after prioritizing appearance controls
  in Settings and preserving dark risk borders. The full results and targeted
  results are recorded separately.
- The extension ZIP is verified against source hashes, checked for CRC errors
  and retains Manifest V3 and the existing CSP. Theme scripts and styles are
  local bundled assets. No new Chrome permissions are requested.

The visual scenarios use synthetic data and isolated browser contexts; they do
not authenticate a real account or exercise live provider/notification delivery.
These checks do not establish formal WCAG conformance. Backend/database code was
not changed for this appearance update.

## Installation

The update backs up changed installed files and verifies the copied extension
and ZIP. The existing `.env` hash is preserved without exposing its contents.
Reload ExtSecure in `chrome://extensions`, close old console tabs and reopen
**Dashboard**. Choose **Dark mode** in the header, or select an appearance under
**Settings → Appearance** and choose **Save preferences**.
