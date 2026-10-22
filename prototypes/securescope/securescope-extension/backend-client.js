import { parseHttpDestination } from "./url-policy.js";
import { validateBackendResponse } from "./backend-response.js";

const LOCAL_BACKEND_ORIGIN = "http://127.0.0.1:8001";
const LOCAL_BACKEND_PREFIX = "/";

// Manual checks can call only the mounted loopback API. A fake fetch makes the
// origin minimization and unavailable-result behaviour testable offline.
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
    const base = new URL(baseUrl);
    if (base.origin !== LOCAL_BACKEND_ORIGIN ||
        base.pathname !== LOCAL_BACKEND_PREFIX ||
        base.username || base.password || base.search || base.hash) return null;
    endpoint = new URL("api/v1/check", base);
  } catch {
    return null;
  }

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
