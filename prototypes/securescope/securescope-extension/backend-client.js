import { parseHttpDestination } from "./url-policy.js";
import { validateBackendResponse } from "./backend-response.js";

const LOCAL_DEV_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// This function is testable with a fake fetch. The service worker currently
// keeps backend calls disabled until the team's API and privacy rules agree.
export async function checkWithBackend(origin, source, {
  baseUrl,
  timeoutMs = 3000,
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
} = {}) {
  const destination = parseHttpDestination(origin);
  if (!destination || destination.origin !== origin) return null;
  if (source !== "visited" && source !== "manual") return null;
  if (typeof fetchImpl !== "function") return null;

  let endpoint;
  try {
    endpoint = new URL("/api/v1/check", baseUrl);
  } catch {
    return null;
  }
  const localHttp = endpoint.protocol === "http:" && LOCAL_DEV_HOSTS.has(endpoint.hostname);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
      (endpoint.protocol !== "https:" && !localHttp)) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(endpoint.href, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: origin, source, checked_at: now() }),
      signal: controller.signal,
    });
    if (!response?.ok) return null;
    return validateBackendResponse(await response.json(), origin);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
