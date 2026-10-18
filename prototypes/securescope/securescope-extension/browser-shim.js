// browser-shim.js
// Minimal cross-browser compatibility shim for the Firefox stretch goal.
//
// Firefox exposes a native, Promise-based `browser` global. Chrome only
// exposes `chrome` — but for the specific APIs this project uses (storage,
// notifications, runtime messaging), `chrome.*` is ALSO Promise-based as of
// Manifest V3. That overlap means this one line is enough to run the same
// code on both browsers, without pulling in the full webextension-polyfill
// library.
//
// chrome.webNavigation is event-based either way (not Promise-based), so
// this shim doesn't change how those listeners are wired up — it only
// matters for the awaited calls (storage, notifications, etc).
export const browserAPI = typeof browser !== "undefined" ? browser : chrome;
