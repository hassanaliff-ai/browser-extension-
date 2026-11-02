import {scoreUrlLocally} from './inline-score.js';

export const INLINE_CHECK = 'SECURESCOPE_CHECK_LINK_ORIGINS';

function webUrl(value) {
  if (typeof value !== 'string' || value.length > 4096) return null;
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && url.hostname && url.hostname.length <= 253 ? url : null;
  } catch { return null; }
}

export function inlineSender(sender, runtime) {
  return sender?.id === runtime.id && sender.frameId === 0 &&
    Number.isInteger(sender.tab?.id) && sender.tab.id >= 0 && !!webUrl(sender.url);
}

export function checkInlineOrigins(origins) {
  if (!Array.isArray(origins) || !origins.length || origins.length > 50)
    throw new Error('Inline checks require between 1 and 50 site origins.');
  const urls = origins.map(origin => {
    const url = webUrl(origin);
    if (!url || url.origin !== origin) throw new Error('Inline checks accept site origins only.');
    return url;
  });
  const results = [...new Map(urls.map(url => [url.origin, url])).values()].map(url => {
    const local = url.hostname === 'localhost' || url.hostname.endsWith('.localhost') ||
      url.hostname === '[::1]' || /^127\./.test(url.hostname);
    const verdict = local ? {severity:'Unknown',reasons:['Local development address is not scanned.']} : scoreUrlLocally(url.origin);
    return {origin:url.origin,...verdict};
  });
  // Pure local rules: no fetch, storage, history, account actions or containment.
  return {results,lookupStatus:'local-only'};
}
