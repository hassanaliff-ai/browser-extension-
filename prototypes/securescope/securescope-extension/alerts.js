// alerts.js
// Owned by: Alerts & UI Lead
//
// background.js (Extension Lead) calls notifyIfRisky(entry) every time a
// site is scored — whether from real-time browsing or a manual check.
// Everything about WHETHER and HOW to alert the user belongs here:
// native notifications, icon badge colour/count, popup highlighting, etc.
//
// Import browserAPI from ./browser-shim.js (not chrome.* directly) so this
// stays cross-browser for the Firefox stretch goal.
//
// entry shape (see ../docs/MESSAGING.md):
//   {
//     url: string,
//     source: "visited" | "manual",
//     tabId: number | null,
//     severity: "Low" | "Medium" | "High" | "Critical",
//     reasons: string[],
//     checkedAt: number
//   }

import { browserAPI } from "./browser-shim.js";

export async function notifyIfRisky(entry) {
  // TODO (Alerts & UI Lead): implement real alerting here.
  //
  // Example starting point:
  //
  // if (entry.severity === "High" || entry.severity === "Critical") {
  //   browserAPI.notifications.create({
  //     type: "basic",
  //     iconUrl: "icons/icon128.png",
  //     title: `SecureScope: ${entry.severity} risk detected`,
  //     message: entry.reasons.join("; ") || entry.url,
  //   });
  // }
  //
  // Icon badge example:
  //
  // browserAPI.action.setBadgeText({ text: entry.severity === "Low" ? "" : "!" });
  // browserAPI.action.setBadgeBackgroundColor({ color: severityColor(entry.severity) });
}
