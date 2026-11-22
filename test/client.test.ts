import { test } from "node:test";
import assert from "node:assert/strict";

import { parseOutcome } from "../src/broker/client";

const creds = {
  accessKeyId: "ASIAEXAMPLE",
  secretAccessKey: "secret",
  sessionToken: "token",
  expiration: "2026-11-22T18:30:48.000Z",
};

test("a refusal at the high-usage confirmation keeps its stage and warnings", () => {
  const o = parseOutcome(
    {
      status: "denied",
      stage: "high-usage-confirmation",
      warnings: ["CPU 92% (limit 70%)"],
      usage: { cpuPct: 92 },
    },
    200,
  );
  assert.deepEqual(o, {
    status: "denied",
    stage: "high-usage-confirmation",
    warnings: ["CPU 92% (limit 70%)"],
  });
});

test("a plain refusal (first push) has no stage or warnings", () => {
  assert.deepEqual(parseOutcome({ status: "denied", planId: "req-1" }, 200), { status: "denied" });
});

test("an approval after a warning carries the warnings through", () => {
  const o = parseOutcome(
    { status: "approved", planId: "req-1", approvedBy: "auth0|x", credentials: creds, warnings: ["memory 85% (limit 80%)"] },
    200,
  );
  assert.equal(o.status, "approved");
  assert.deepEqual(o.status === "approved" && o.warnings, ["memory 85% (limit 80%)"]);
});

test("malformed warnings from the broker are dropped, not passed on", () => {
  const o = parseOutcome({ status: "expired", warnings: [1, { x: 2 }] }, 200);
  assert.deepEqual(o, { status: "expired" });
});
