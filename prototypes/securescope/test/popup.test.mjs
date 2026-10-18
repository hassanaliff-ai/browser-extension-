import test from "node:test";
import assert from "node:assert/strict";

class FakeElement {
  constructor() {
    this.listeners = {};
    this.children = [];
    this.dataset = {};
    this.hidden = false;
    this.textContent = "";
    this.value = "";
    this.disabled = false;
  }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  replaceChildren(...items) { this.children = items; }
  append(...items) { this.children.push(...items); }
}

test("popup displays local coverage and never renders raw HTML", async () => {
  const ids = [
    "check-form", "url-input", "check-button", "result", "result-severity",
    "result-url", "result-coverage", "result-reasons", "history-list",
    "history-empty", "clear-history",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new FakeElement()]));
  const state = { visitHistory: [{
    url: "https://old.example", source: "visited", severity: "Low",
    checkedAt: Date.now() - 8 * 24 * 60 * 60 * 1000,
  }] };

  globalThis.document = {
    getElementById(id) { return elements[id]; },
    createElement() { return new FakeElement(); },
  };
  globalThis.chrome = {
    runtime: { async sendMessage({ url }) {
      assert.equal(url, "https://example.com/path?token=secret");
      const entry = {
        url: "https://example.com", source: "manual", severity: "Low",
        lookupStatus: "local-only", reasons: ["<script>unsafe</script>"], checkedAt: Date.now(),
      };
      state.visitHistory = [entry];
      return entry;
    } },
    storage: { local: {
      async get() { return { visitHistory: state.visitHistory }; },
      async remove() { state.visitHistory = []; },
    } },
  };

  await import("../securescope-extension/popup.js");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["history-list"].children.length, 0);
  elements["url-input"].value = "https://example.com/path?token=secret";
  await elements["check-form"].listeners.submit({ preventDefault() {} });

  assert.equal(elements["result-url"].textContent, "https://example.com");
  assert.match(elements["result-coverage"].textContent, /does not prove the site is safe/);
  assert.equal(elements["result-reasons"].children[0].textContent, "<script>unsafe</script>");
  assert.equal(elements["history-list"].children[0].children[0].textContent, "https://example.com");

  await elements["clear-history"].listeners.click();
  assert.equal(elements["history-empty"].hidden, false);
  assert.equal(elements["history-list"].children.length, 0);
});
