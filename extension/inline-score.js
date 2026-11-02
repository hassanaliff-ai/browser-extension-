// Local SecureScope indicators adapted from the standalone prototype.
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

export function scoreUrlLocally(rawUrl) {
  const reasons = [];
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { severity: "Unknown", reasons: ["Could not parse URL"] };
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
    reasons.push(`Uses a TLD (.${tld}) included in the local warning rules`);
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

