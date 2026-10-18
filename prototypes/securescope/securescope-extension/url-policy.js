// Minimize automatically observed destinations before they leave this module.
// A site origin contains the scheme, hostname and optional port. It excludes
// credentials, path, query and fragment, which can contain private data.
export function parseHttpDestination(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0 || rawUrl.length > 4096) {
    return null;
  }

  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (!parsed.hostname || parsed.hostname.length > 253) return null;

    return {
      origin: parsed.origin,
      hostname: parsed.hostname.toLowerCase(),
    };
  } catch {
    return null;
  }
}

// Loopback addresses are local services, outside SecureScope's public-site
// phishing score. Do not interpret their numeric address as a remote IP signal.
export function isLoopbackHostname(hostname) {
  if (typeof hostname !== "string") return false;
  const host = hostname.toLowerCase();
  return host === "localhost" || host.endsWith(".localhost") ||
    host === "[::1]" || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(host);
}
