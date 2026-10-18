// Treat the backend as an external data source. Reject incomplete or
// unexpected responses before they affect a browser warning.
const SEVERITIES = new Set(["Low", "Medium", "High", "Critical"]);
const LOOKUP_STATUSES = new Set(["complete", "partial"]);

export function validateBackendResponse(data, requestedOrigin) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  if (!SEVERITIES.has(data.severity)) return null;
  if (!LOOKUP_STATUSES.has(data.lookup_status)) return null;
  if (data.origin !== undefined && data.origin !== requestedOrigin) return null;
  if (data.cached !== undefined && typeof data.cached !== "boolean") return null;
  if (!Array.isArray(data.reasons) || data.reasons.length > 10 ||
      data.reasons.some((reason) =>
        typeof reason !== "string" || !reason.trim() || reason.length > 200)) {
    return null;
  }

  return {
    severity: data.severity,
    reasons: data.reasons.map((reason) => reason.trim()),
    lookupStatus: data.lookup_status,
    cached: data.cached === true,
  };
}
