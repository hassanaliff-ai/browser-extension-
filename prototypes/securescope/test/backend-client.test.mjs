import test from "node:test";
import assert from "node:assert/strict";
import { checkWithBackend } from "../securescope-extension/backend-client.js";

const baseUrl = "http://localhost:8000";

test("API client sends only the site origin and accepts a valid response", async () => {
  let sent;
  const fetchImpl = async (url, options) => {
    sent = { url, options };
    return { ok: true, json: async () => ({
      severity: "High", reasons: ["Known malicious domain"],
      lookup_status: "partial", origin: "https://example.com",
    }) };
  };
  const result = await checkWithBackend("https://example.com", "manual", {
    baseUrl, fetchImpl, now: () => 123,
  });
  assert.equal(sent.url, "http://localhost:8000/api/v1/check");
  assert.deepEqual(JSON.parse(sent.options.body), {
    url: "https://example.com", source: "manual", checked_at: 123,
  });
  assert.equal(result.severity, "High");
  assert.equal(result.lookupStatus, "partial");
});

test("API client does not send private URL parts or use cleartext remote servers", async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error("must not fetch"); };
  assert.equal(await checkWithBackend("https://example.com/reset?token=secret", "manual", {
    baseUrl, fetchImpl,
  }), null);
  assert.equal(await checkWithBackend("https://example.com", "manual", {
    baseUrl: "http://remote.example", fetchImpl,
  }), null);
  assert.equal(calls, 0);
});

test("API client returns no backend verdict on timeout or malformed response", async () => {
  const timeoutFetch = (_url, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
  });
  assert.equal(await checkWithBackend("https://example.com", "visited", {
    baseUrl, fetchImpl: timeoutFetch, timeoutMs: 10,
  }), null);
  assert.equal(await checkWithBackend("https://example.com", "visited", {
    baseUrl, fetchImpl: async () => ({ ok: true, json: async () => ({
      severity: "Safe", reasons: [], lookup_status: "complete",
    }) }),
  }), null);
});
