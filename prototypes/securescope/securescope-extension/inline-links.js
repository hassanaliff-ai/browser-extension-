// Page links are untrusted data. Only their site origins are sent to the
// extension worker. No page text, URL paths, queries or fragments are sent.
(() => {
  const browserAPI = typeof browser !== "undefined" ? browser : chrome;
  const MAX_ORIGINS_PER_PAGE = 500;
  const MAX_ANCHORS_PER_PAGE = 2000;
  const BATCH_SIZE = 50;
  const BADGE_LEVELS = new Set(["Medium", "High", "Critical"]);

  const currentOriginByAnchor = new WeakMap();
  const countedAnchors = new WeakSet();
  let countedAnchorCount = 0;
  const badgeByAnchor = new WeakMap();
  const verdictByOrigin = new Map();
  const waitingByOrigin = new Map();
  const queue = [];
  let scheduled = false;
  let draining = false;

  function linkOrigin(anchor) {
    try {
      if (typeof anchor.href !== "string") return null;
      const url = new URL(anchor.href);
      if (url.protocol !== "http:" && url.protocol !== "https:") return null;
      if (!url.hostname || url.hostname.length > 253) return null;
      return url.origin;
    } catch {
      return null;
    }
  }

  function removeBadge(anchor) {
    const existing = badgeByAnchor.get(anchor);
    if (existing) existing.remove();
    badgeByAnchor.delete(anchor);
  }

  function applyVerdict(anchor, origin, verdict) {
    if (currentOriginByAnchor.get(anchor) !== origin || !anchor.isConnected) return;
    removeBadge(anchor);
    if (!BADGE_LEVELS.has(verdict?.severity)) return;

    const badge = document.createElement("span");
    badge.className = "securescope-inline-badge";
    badge.dataset.severity = verdict.severity.toLowerCase();
    badge.textContent = `SecureScope: ${verdict.severity} risk`;
    badge.setAttribute("role", "note");
    anchor.insertAdjacentElement("afterend", badge);
    badgeByAnchor.set(anchor, badge);
  }

  function scheduleDrain() {
    if (scheduled || draining) return;
    scheduled = true;
    setTimeout(() => {
      scheduled = false;
      void drainQueue();
    }, 50);
  }

  async function drainQueue() {
    if (draining) return;
    draining = true;
    try {
      while (queue.length) {
        const origins = queue.splice(0, BATCH_SIZE);
        let returned = new Map();
        try {
          const reply = await browserAPI.runtime.sendMessage({
            type: "SECURESCOPE_CHECK_LINK_ORIGINS",
            origins,
          });
          if (Array.isArray(reply?.results)) {
            returned = new Map(reply.results
              .filter((item) => origins.includes(item?.origin))
              .map((item) => [item.origin, item]));
          }
        } catch {
          // No badge is safer than implying a failed check found no risk.
        }

        for (const origin of origins) {
          const verdict = returned.get(origin) || { severity: "Unknown", reasons: [] };
          verdictByOrigin.set(origin, verdict);
          for (const anchor of waitingByOrigin.get(origin) || []) {
            applyVerdict(anchor, origin, verdict);
          }
          waitingByOrigin.delete(origin);
        }
      }
    } finally {
      draining = false;
      if (queue.length) scheduleDrain();
    }
  }

  function inspectAnchor(anchor) {
    if (anchor.closest("[contenteditable]")) return true;
    if (!countedAnchors.has(anchor)) {
      if (countedAnchorCount >= MAX_ANCHORS_PER_PAGE) return false;
      countedAnchors.add(anchor);
      countedAnchorCount++;
    }
    const origin = linkOrigin(anchor);
    if (currentOriginByAnchor.get(anchor) === origin) return true;
    currentOriginByAnchor.set(anchor, origin);
    removeBadge(anchor);
    if (!origin) return true;

    if (verdictByOrigin.has(origin)) {
      applyVerdict(anchor, origin, verdictByOrigin.get(origin));
      return true;
    }
    if (!waitingByOrigin.has(origin)) {
      if (verdictByOrigin.size + waitingByOrigin.size >= MAX_ORIGINS_PER_PAGE) return true;
      waitingByOrigin.set(origin, new Set());
      queue.push(origin);
    }
    waitingByOrigin.get(origin).add(anchor);
    scheduleDrain();
    return true;
  }

  function inspectNode(node) {
    if (!(node instanceof Element)) return;
    if (node.matches("a[href]") && !inspectAnchor(node)) return;
    if (countedAnchorCount >= MAX_ANCHORS_PER_PAGE) return;
    for (const anchor of node.querySelectorAll("a[href]")) {
      if (!inspectAnchor(anchor)) break;
    }
  }

  inspectNode(document.documentElement);
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === "attributes") {
        if (mutation.target.matches("a")) inspectAnchor(mutation.target);
      } else {
        for (const node of mutation.addedNodes) inspectNode(node);
      }
    }
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["href"],
  });
})();
