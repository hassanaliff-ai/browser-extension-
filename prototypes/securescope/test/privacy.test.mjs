import test from "node:test";
import assert from "node:assert/strict";
import { isLoopbackHostname, parseHttpDestination } from "../securescope-extension/url-policy.js";

test("destination parser removes sensitive URL components from every site", () => {
  assert.equal(
    parseHttpDestination("https://user:password@example.com/reset?token=secret#section")?.origin,
    "https://example.com",
  );
  assert.equal(
    parseHttpDestination("https://www.google.com/search?q=private+terms")?.origin,
    "https://www.google.com",
  );
  assert.equal(parseHttpDestination("http://example.com:8080/a?b=c")?.origin, "http://example.com:8080");
});

test("destination parser rejects unsupported and malformed inputs", () => {
  for (const value of ["file:///secret", "chrome://history", "javascript:alert(1)", "not a url", ""]) {
    assert.equal(parseHttpDestination(value), null);
  }
});

test("only loopback hosts are excluded from public-site scoring", () => {
  for (const host of ["localhost", "api.localhost", "127.0.0.1", "127.77.0.1", "[::1]"]) {
    assert.equal(isLoopbackHostname(host), true, host);
  }
  for (const host of ["128.0.0.1", "192.168.1.1", "127.0.0.1.evil.example", "example.com"]) {
    assert.equal(isLoopbackHostname(host), false, host);
  }
});

test("service worker sends only manual origins to loopback and clears legacy full-URL history", async () => {
  let messageListener;
  let visitListener;
  let alarmListener;
  let cleanupAlarm;
  const fetchCalls = [];
  const state = {
    visitHistory: [{ url: "https://example.com/?token=old-secret", checkedAt: Date.now() }],
  };

  globalThis.chrome = {
    runtime: {
      onInstalled: { addListener() {} },
      onMessage: { addListener(fn) { messageListener = fn; } },
    },
    webNavigation: { onCompleted: { addListener(fn) { visitListener = fn; } } },
    alarms: {
      onAlarm: { addListener(fn) { alarmListener = fn; } },
      async get() { return cleanupAlarm; },
      async create(name, details) { cleanupAlarm = { name, scheduledTime: details.when }; },
      async clear() { cleanupAlarm = undefined; return true; },
    },
    storage: { local: {
      async get(key) { return { [key]: state[key] }; },
      async set(value) { Object.assign(state, value); },
      async remove(key) { delete state[key]; },
      async setAccessLevel() {},
    } },
  };
  globalThis.fetch = async (url, options) => {
    fetchCalls.push({ url, body: JSON.parse(options.body) });
    return { ok: false, status: 503 };
  };

  await import("../securescope-extension/background.js");
  assert.equal(typeof visitListener, "function");
  assert.equal(typeof messageListener, "function");
  assert.equal(typeof alarmListener, "function");

  const result = await new Promise((resolve) => {
    const keepOpen = messageListener(
      { type: "SECURESCOPE_CHECK_URL", url: "https://user:password@example.com/reset?token=new-secret#part" },
      {}, resolve,
    );
    assert.equal(keepOpen, true);
  });
  assert.equal(result.url, "https://example.com");
  assert.equal(result.lookupStatus, "backend-unavailable");
  assert.deepEqual(fetchCalls[0], {
    url: "http://127.0.0.1:8001/api/v1/check",
    body: { url: "https://example.com", source: "manual", checked_at: fetchCalls[0].body.checked_at },
  });
  assert.equal(state.visitHistory.length, 1);

  const local = await new Promise((resolve) => {
    messageListener({ type: "SECURESCOPE_CHECK_URL", url: "http://127.0.0.1:8000/docs" }, {}, resolve);
  });
  assert.equal(local.severity, "Unknown");
  assert.equal(local.lookupStatus, "not-scanned");
  assert.equal(state.visitHistory.length, 1);
  assert.equal(state.visitHistory[0].url, "https://example.com");
  assert.equal(JSON.stringify(state).includes("secret"), false);
  assert.equal(state.privacyMigrationVersion, 1);
  assert.equal(cleanupAlarm?.name, "securescope-history-cleanup");

  const invalid = await new Promise((resolve) => {
    messageListener({ type: "SECURESCOPE_CHECK_URL", url: "file:///private" }, {}, resolve);
  });
  assert.equal(invalid.severity, "Unknown");
  assert.equal(invalid.url, "");
  assert.equal(state.visitHistory.length, 1);

  const inline = await new Promise((resolve) => {
    messageListener({
      type: "SECURESCOPE_CHECK_LINK_ORIGINS",
      origins: ["https://paypol.com", "http://127.0.0.1:8000", "https://example.com/path?token=secret"],
    }, { tab: { id: 4 }, frameId: 0 }, resolve);
  });
  assert.equal(inline.lookupStatus, "local-only");
  assert.deepEqual(inline.results.map((item) => item.origin), ["https://paypol.com"]);
  assert.equal(state.visitHistory.length, 1);
  assert.equal(fetchCalls.length, 1);

  const embeddedBrand = await new Promise((resolve) => {
    messageListener({ type: "SECURESCOPE_CHECK_URL", url: "https://paypal.com.evil.example/login" }, {}, resolve);
  });
  assert.equal(embeddedBrand.severity, "High");
  assert.match(embeddedBrand.reasons.join(" "), /embeds "paypal\.com"/);
  assert.equal(embeddedBrand.url, "https://paypal.com.evil.example");

  const realBrand = await new Promise((resolve) => {
    messageListener({ type: "SECURESCOPE_CHECK_URL", url: "https://www.paypal.com/help" }, {}, resolve);
  });
  assert.equal(realBrand.severity, "Low");
  assert.equal(fetchCalls.length, 3);
  assert.deepEqual(fetchCalls.map((call) => call.body.url), [
    "https://example.com", "https://paypal.com.evil.example", "https://www.paypal.com",
  ]);

  // An old entry must be removed by the alarm even if no new site is visited.
  for (const entry of state.visitHistory) {
    entry.checkedAt = Date.now() - 8 * 24 * 60 * 60 * 1000;
  }
  alarmListener({ name: "securescope-history-cleanup" });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(state.visitHistory, []);
  assert.equal(cleanupAlarm, undefined);
});
