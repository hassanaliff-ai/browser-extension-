import { browserAPI } from "./browser-shim.js";

const form = document.getElementById("check-form");
const input = document.getElementById("url-input");
const checkButton = document.getElementById("check-button");
const result = document.getElementById("result");
const severity = document.getElementById("result-severity");
const resultUrl = document.getElementById("result-url");
const coverage = document.getElementById("result-coverage");
const reasons = document.getElementById("result-reasons");
const historyList = document.getElementById("history-list");
const historyEmpty = document.getElementById("history-empty");
const clearButton = document.getElementById("clear-history");

const SEVERITIES = new Set(["Low", "Medium", "High", "Critical", "Unknown"]);
const HISTORY_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function renderResult(entry) {
  const level = SEVERITIES.has(entry?.severity) ? entry.severity : "Unknown";
  result.hidden = false;
  result.dataset.severity = level.toLowerCase();
  severity.textContent = level;
  resultUrl.textContent = typeof entry?.url === "string" && entry.url ? entry.url : "URL not checked";

  const lookupStatus = entry?.lookupStatus;
  if (level === "Unknown") {
    coverage.textContent = "This URL could not be checked. No safety conclusion is available.";
  } else if (lookupStatus === "backend-unavailable") {
    coverage.textContent = "Backend evidence is unavailable. Only local warning signs were checked; this does not prove the site is safe.";
  } else if (lookupStatus === "complete" || lookupStatus === "partial") {
    coverage.textContent = lookupStatus === "partial"
      ? "Backend evidence is partial. This result does not certify the site as safe."
      : "Backend evidence was checked. This result does not certify the site as safe.";
  } else if (level === "Low") {
    coverage.textContent = "No local warning signs found. Reputation and RDAP checks are not active; this does not prove the site is safe.";
  } else {
    coverage.textContent = "Local warning signs found. Reputation and RDAP checks are not active yet.";
  }

  reasons.replaceChildren();
  const safeReasons = Array.isArray(entry?.reasons)
    ? entry.reasons.filter((item) => typeof item === "string").slice(0, 5)
    : [];
  for (const reason of safeReasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    reasons.append(item);
  }
}

async function refreshHistory() {
  const { visitHistory = [] } = await browserAPI.storage.local.get("visitHistory");
  const now = Date.now();
  const recent = Array.isArray(visitHistory)
    ? visitHistory.filter((entry) => typeof entry?.checkedAt === "number" &&
        now >= entry.checkedAt && now - entry.checkedAt < HISTORY_TTL_MS).slice(0, 5)
    : [];
  historyList.replaceChildren();
  historyEmpty.hidden = recent.length > 0;
  for (const entry of recent) {
    const item = document.createElement("li");
    const site = document.createElement("span");
    site.className = "history-url";
    site.textContent = typeof entry.url === "string" ? entry.url : "Unknown site";
    const meta = document.createElement("span");
    meta.className = "history-meta";
    const level = SEVERITIES.has(entry.severity) ? entry.severity : "Unknown";
    const status = entry.lookupStatus === "backend-unavailable" ? "Backend unavailable"
      : entry.lookupStatus === "complete" ? "Backend checked"
      : entry.lookupStatus === "partial" ? "Partial evidence" : "Local only";
    meta.textContent = `${level} · ${entry.source === "manual" ? "Manual" : "Visited"} · ${status}`;
    item.append(site, meta);
    historyList.append(item);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const rawUrl = input.value.trim();
  if (!rawUrl) return;

  checkButton.disabled = true;
  checkButton.textContent = "Checking…";
  try {
    const entry = await browserAPI.runtime.sendMessage({ type: "SECURESCOPE_CHECK_URL", url: rawUrl });
    renderResult(entry);
    await refreshHistory();
  } catch {
    renderResult({ severity: "Unknown", reasons: ["The extension could not complete this check."] });
  } finally {
    checkButton.disabled = false;
    checkButton.textContent = "Check link";
  }
});

clearButton.addEventListener("click", async () => {
  await browserAPI.storage.local.remove("visitHistory");
  await refreshHistory();
});

refreshHistory().catch(() => {
  historyEmpty.textContent = "Recent checks are unavailable.";
});
