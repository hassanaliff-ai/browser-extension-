import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

class FakeElement {
  constructor(kind, href = "") {
    this.kind = kind;
    this.href = href;
    this.isConnected = true;
    this.dataset = {};
    this.anchors = [];
    this.removed = false;
  }
  matches(selector) { return this.kind === "anchor" && (selector === "a" || selector === "a[href]"); }
  querySelectorAll() { return this.anchors; }
  closest() { return null; }
  insertAdjacentElement(_position, badge) { this.badge = badge; }
  setAttribute() {}
  remove() { this.removed = true; }
}

test("inline checker sends only site origins and handles added or changed links", async () => {
  const first = new FakeElement("anchor", "https://paypol.com/reset?token=secret");
  const root = new FakeElement("root");
  root.anchors = [first];
  const sent = [];
  let observerCallback;
  const document = {
    documentElement: root,
    createElement() { return new FakeElement("badge"); },
  };
  const chrome = { runtime: { async sendMessage(message) {
    sent.push(message);
    return { results: message.origins.map((origin) => ({
      origin, severity: origin === "https://paypol.com" ? "High" : "Low", reasons: [],
    })) };
  } } };
  class FakeObserver {
    constructor(callback) { observerCallback = callback; }
    observe() {}
  }

  const script = readFileSync(new URL("../securescope-extension/inline-links.js", import.meta.url), "utf8");
  runInNewContext(script, { chrome, document, Element: FakeElement, MutationObserver: FakeObserver, URL, setTimeout });
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.deepEqual(Array.from(sent[0].origins), ["https://paypol.com"]);
  assert.equal(first.badge.textContent, "SecureScope: High risk");

  const second = new FakeElement("anchor", "https://paypol.com/another?private=yes");
  observerCallback([{ type: "childList", addedNodes: [second] }]);
  assert.equal(second.badge.textContent, "SecureScope: High risk");
  assert.equal(sent.length, 1);

  first.href = "https://example.com/ordinary";
  observerCallback([{ type: "attributes", target: first }]);
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(first.badge.removed, true);
  assert.deepEqual(Array.from(sent[1].origins), ["https://example.com"]);
});

test("inline checker caps anchors even when thousands share one origin", async () => {
  const anchors = Array.from({ length: 2100 }, (_, i) =>
    new FakeElement("anchor", `https://paypol.com/path-${i}`));
  const root = new FakeElement("root");
  root.anchors = anchors;
  let messages = 0;
  let observerCallback;
  const document = {
    documentElement: root,
    createElement() { return new FakeElement("badge"); },
  };
  const chrome = { runtime: { async sendMessage(message) {
    messages++;
    assert.equal(message.origins.length, 1);
    return { results: [{ origin: message.origins[0], severity: "High", reasons: [] }] };
  } } };
  class FakeObserver {
    constructor(callback) { observerCallback = callback; }
    observe() {}
  }

  const script = readFileSync(new URL("../securescope-extension/inline-links.js", import.meta.url), "utf8");
  runInNewContext(script, { chrome, document, Element: FakeElement, MutationObserver: FakeObserver, URL, setTimeout });
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(messages, 1);
  assert.equal(anchors[0].badge.textContent, "SecureScope: High risk");
  assert.equal(anchors[1999].badge.textContent, "SecureScope: High risk");
  assert.equal(anchors[2000].badge, undefined);

  // A link already counted can still be rechecked after its destination changes.
  const oldBadge = anchors[0].badge;
  anchors[0].href = "https://example.com";
  observerCallback([{ type: "attributes", target: anchors[0] }]);
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(messages, 2);
  assert.equal(oldBadge.removed, true);
  assert.notEqual(anchors[0].badge, oldBadge);
  assert.equal(anchors[0].badge.textContent, "SecureScope: High risk");
});
