import test from "node:test";
import assert from "node:assert/strict";
import { validateBackendResponse } from "../securescope-extension/backend-response.js";

const origin = "https://example.com";

test("accepts a complete or partial result with bounded plain-text reasons", () => {
  assert.deepEqual(validateBackendResponse({
    severity: "Medium", reasons: [" Recently registered domain "],
    lookup_status: "partial", cached: false, origin,
  }, origin), {
    severity: "Medium", reasons: ["Recently registered domain"],
    lookupStatus: "partial", cached: false,
  });
});

test("rejects malformed, mismatched, or misleading backend results", () => {
  const valid = { severity: "Low", reasons: [], lookup_status: "complete" };
  for (const data of [
    { ...valid, severity: "Safe" },
    { ...valid, lookup_status: "unknown" },
    { ...valid, reasons: "No problem" },
    { ...valid, reasons: ["<script>", 12] },
    { ...valid, reasons: ["x".repeat(201)] },
    { ...valid, reasons: Array(11).fill("reason") },
    { ...valid, cached: "false" },
    { ...valid, origin: "https://different.example" },
    null,
  ]) {
    assert.equal(validateBackendResponse(data, origin), null);
  }
});
