// background.js
// Extension Lead — detect site visits, score locally, and hand off to
// notifyIfRisky() (owned by the Alerts & UI Lead) and to the popup (via
// chrome.storage + runtime messages).
// Backend requests remain disabled in this privacy-baseline build.
//
// See ../docs/API_CONTRACT.md for the exact backend request/response shape,
// and ../docs/MESSAGING.md for how the popup and alerts.js are meant to
// talk to this file.

import { browserAPI } from "./browser-shim.js";
import { notifyIfRisky } from "./alerts.js";
import { isLoopbackHostname, parseHttpDestination } from "./url-policy.js";
import { checkWithBackend } from "./backend-client.js";

const MAX_HISTORY = 50;
const HISTORY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const HISTORY_CLEANUP_ALARM = "securescope-history-cleanup";

// TODO (Extension Lead / Backend Lead): update once the real backend is
// deployed. Also update host_permissions in manifest.json to match.
const BACKEND_BASE_URL = "http://localhost:8000";
const BACKEND_TIMEOUT_MS = 3000;
// Keep network requests off until the team agrees the API, data policy and
// allowed reputation source. This first build only evaluates URLs locally.
const BACKEND_ENABLED = false;

const SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"];

browserAPI.runtime.onInstalled.addListener(() => {
  console.log("[SecureScope] extension installed/updated, background worker running");
});

browserAPI.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HISTORY_CLEANUP_ALARM) {
    void pruneHistory().catch((err) => console.error("[SecureScope] history cleanup failed:", err));
  }
});

console.log("[SecureScope] background service worker started");

// Content scripts added later should not be able to read browsing history.
if (browserAPI.storage.local.setAccessLevel) {
  browserAPI.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })
    .catch((err) => console.log("[SecureScope] storage access restriction unavailable:", err.message));
}

// --- Real-time detection of every site visited -----------------------

browserAPI.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return; // top-level frame only, not iframes
  checkUrl(details.url, "visited", details.tabId)
    .catch((err) => console.error("[SecureScope] visit check failed:", err));
});

// --- Manual checks, e.g. from the popup's "check this link" box -------
// Contract: sendMessage({ type: "SECURESCOPE_CHECK_URL", url }) -> entry
// See docs/MESSAGING.md.

browserAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "SECURESCOPE_CHECK_URL" && !sender.tab && typeof message.url === "string") {
    checkUrl(message.url, "manual")
      .then(sendResponse)
      .catch(() => sendResponse({ url: "", source: "manual", severity: "Unknown", reasons: ["Check failed"], checkedAt: Date.now() }));
    return true; // keep the message channel open for the async response
  }

  if (message && message.type === "SECURESCOPE_CHECK_LINK_ORIGINS" &&
      sender.tab && sender.frameId === 0 && Array.isArray(message.origins) &&
      message.origins.length <= 50) {
    const results = message.origins.map((origin) => {
      const parsed = parseHttpDestination(origin);
      if (!parsed || parsed.origin !== origin || isLoopbackHostname(parsed.hostname)) return null;
      const local = scoreUrlLocally(origin);
      return { origin, severity: local.severity, reasons: local.reasons };
    }).filter(Boolean);
    sendResponse({ results, lookupStatus: "local-only" });
    return false;
  }
});

// --- Core pipeline: local score + backend check + merge + store -------

async function checkUrl(rawUrl, source, tabId = null) {
  const destination = parseHttpDestination(rawUrl);
  if (!destination) {
    return { url: "", source, severity: "Unknown", reasons: ["Not a checkable HTTP or HTTPS URL"], checkedAt: Date.now() };
  }

  const displayUrl = destination.origin;
  if (isLoopbackHostname(destination.hostname)) {
    // Local development pages are neither public-site Low nor raw-IP High.
    // Do not persist them, query the backend, or issue a warning.
    return {
      url: displayUrl, source, severity: "Unknown",
      reasons: ["Local development address is outside website risk scoring"],
      lookupStatus: "not-scanned", checkedAt: Date.now(),
    };
  }
  const local = scoreUrlLocally(rawUrl);
  const backend = BACKEND_ENABLED ? await checkWithBackend(displayUrl, source, {
    baseUrl: BACKEND_BASE_URL,
    timeoutMs: BACKEND_TIMEOUT_MS,
  }) : null;
  const merged = mergeVerdicts(local, backend);

  const reasonText = merged.reasons.length ? ` (${merged.reasons.join("; ")})` : "";
  const backendNote = backend ? "" : " [local only]";
  console.log(`[SecureScope] ${source}: ${displayUrl} -> ${merged.severity}${reasonText}${backendNote}`);

  const entry = {
    url: displayUrl,
    source,
    tabId,
    severity: merged.severity,
    reasons: merged.reasons,
    lookupStatus: backend?.lookupStatus ?? "local-only",
    checkedAt: Date.now(),
  };

  await appendToHistory(entry);

  try {
    await notifyIfRisky(entry);
  } catch (err) {
    console.log("[SecureScope] notifyIfRisky threw, continuing:", err.message);
  }

  return entry;
}

// Earlier prototype versions stored full URLs. Clear that old history once
// before writing privacy-minimized entries. Keep the queue ordered so a
// simultaneous navigation cannot race with the migration.
let historyWrite = (async () => {
  const { privacyMigrationVersion } = await browserAPI.storage.local.get("privacyMigrationVersion");
  if (privacyMigrationVersion !== 1) {
    await browserAPI.storage.local.remove("visitHistory");
    await browserAPI.storage.local.set({ privacyMigrationVersion: 1 });
  }
})();

function validRecentHistory(history, now) {
  return (Array.isArray(history) ? history : []).filter((item) => {
    if (!item || typeof item.checkedAt !== "number" ||
        now < item.checkedAt || now - item.checkedAt >= HISTORY_TTL_MS) return false;
    const destination = parseHttpDestination(item.url);
    return destination?.origin === item.url && !isLoopbackHostname(destination.hostname);
  }).slice(0, MAX_HISTORY);
}

async function scheduleHistoryCleanup(history) {
  const nextExpiry = history.length
    ? Math.min(...history.map((item) => item.checkedAt + HISTORY_TTL_MS))
    : null;
  const existing = await browserAPI.alarms.get(HISTORY_CLEANUP_ALARM);
  if (nextExpiry === null) {
    if (existing) await browserAPI.alarms.clear(HISTORY_CLEANUP_ALARM);
    return;
  }
  const when = Math.max(nextExpiry, Date.now() + 1000);
  if (!existing || Math.abs(existing.scheduledTime - when) > 1000) {
    await browserAPI.alarms.create(HISTORY_CLEANUP_ALARM, { when });
  }
}

function queueHistoryUpdate(update) {
  historyWrite = historyWrite.catch(() => {}).then(update);
  return historyWrite;
}

async function pruneHistory() {
  return queueHistoryUpdate(async () => {
    const { visitHistory = [] } = await browserAPI.storage.local.get("visitHistory");
    const recent = validRecentHistory(visitHistory, Date.now());
    if (!Array.isArray(visitHistory) || recent.length !== visitHistory.length) {
      await browserAPI.storage.local.set({ visitHistory: recent });
    }
    await scheduleHistoryCleanup(recent);
  });
}

// Chrome may suspend or restart this worker, and alarms may disappear after an
// update. Recheck stored results and recreate the next expiry alarm on startup.
void pruneHistory().catch((err) => console.error("[SecureScope] history cleanup failed:", err));

async function appendToHistory(entry) {
  return queueHistoryUpdate(async () => {
    const { visitHistory = [] } = await browserAPI.storage.local.get("visitHistory");
    const recent = validRecentHistory(visitHistory, entry.checkedAt);
    const next = [entry, ...recent].slice(0, MAX_HISTORY);
    await browserAPI.storage.local.set({ visitHistory: next });
    await scheduleHistoryCleanup(next).catch((err) =>
      console.error("[SecureScope] could not schedule history cleanup:", err));
  });
}

// --- Backend integration (planned next phase) ---------------------------
// Follows docs/API_CONTRACT.md. If the backend is down/unreachable/slow,
// we fail soft and keep using the local verdict — a flaky backend should
// never break the extension's core protection.

function mergeVerdicts(local, backend) {
  if (!backend) return { severity: local.severity, reasons: local.reasons };
  const severity = SEVERITY_ORDER.indexOf(backend.severity) >= SEVERITY_ORDER.indexOf(local.severity)
    ? backend.severity
    : local.severity;
  const reasons = Array.from(new Set([...local.reasons, ...backend.reasons]));
  return { severity, reasons };
}

// --- Local risk-scoring heuristics (Step 3) -----------------------------

const PROTECTED_BRANDS = [
  "google", "paypal", "microsoft", "apple", "amazon",
  "facebook", "instagram", "netflix", "chase", "bankofamerica",
];

const SUSPICIOUS_TLDS = [
  "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
];

const KNOWN_URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
];

function scoreUrlLocally(rawUrl) {
  const reasons = [];
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { severity: "Low", reasons: ["Could not parse URL"] };
  }

  const host = url.hostname.toLowerCase();

  if (isIpLiteral(host)) {
    reasons.push("Destination is a raw IP address, not a domain name");
  }

  if (host.includes("xn--")) {
    reasons.push("Internationalized domain (punycode) — verify it isn't a lookalike");
  }

  const tld = host.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    reasons.push(`Uses a TLD (.${tld}) frequently abused for phishing`);
  }

  if (KNOWN_URL_SHORTENERS.includes(host)) {
    reasons.push("Shortened link — real destination is hidden");
  }

  const mainLabel = host.replace(/^www\./, "").split(".")[0];
  // A hostname such as paypal.com.evil.example belongs to evil.example,
  // despite starting with the familiar paypal.com label sequence. Keep this
  // as a separate signal so the exact-brand shortcut below cannot miss it.
  const labels = host.split(".");
  for (const brand of PROTECTED_BRANDS) {
    if (labels.some((label, index) =>
      label === brand && labels[index + 1] === "com" && index + 2 < labels.length)) {
      reasons.push(`Hostname embeds "${brand}.com" before another domain (possible impersonation)`);
      break;
    }
  }

  for (const brand of PROTECTED_BRANDS) {
    if (mainLabel === brand) continue;
    const distance = levenshtein(mainLabel, brand);
    if (distance > 0 && distance <= 2 && Math.abs(mainLabel.length - brand.length) <= 2) {
      reasons.push(`Domain closely resembles "${brand}" (possible typosquat)`);
      break;
    }
  }

  const hasHighSignal = reasons.some(r =>
    r.includes("raw IP") || r.includes("typosquat") || r.includes("embeds"));
  let severity = "Low";
  if (reasons.length >= 2) severity = "Critical";
  else if (hasHighSignal) severity = "High";
  else if (reasons.length === 1) severity = "Medium";

  return { severity, reasons };
}

function isIpLiteral(host) {
  const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipv6 = /^\[[0-9a-fA-F:]+\]$/;
  return ipv4.test(host) || ipv6.test(host);
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

// --- Testing only: expose key functions to the service worker console ---
// (ES modules don't auto-attach top-level functions to global scope.)
