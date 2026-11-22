import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_THRESHOLDS,
  GUARDED_ACTIONS,
  assessUsage,
  highUsageBindingMessage,
  thresholdsFromEnv,
  type Usage,
} from "../src/broker/usage";

const T = DEFAULT_THRESHOLDS; // cpu 70, mem 80, net 50
const ID = "i-0747af78fd8763865";
const usage = (u: Partial<Usage>): Usage => ({
  cpuPct: null,
  memPct: null,
  netMbps: null,
  windowMinutes: 15,
  ...u,
});

test("an idle instance needs no second confirmation", () => {
  const a = assessUsage(usage({ cpuPct: 3, memPct: 20, netMbps: 0.1 }), T);
  assert.equal(a.high, false);
  assert.deepEqual(a.reasons, []);
});

test("each metric on its own can trigger the warning", () => {
  assert.equal(assessUsage(usage({ cpuPct: 92 }), T).high, true);
  assert.equal(assessUsage(usage({ memPct: 85 }), T).high, true);
  assert.equal(assessUsage(usage({ netMbps: 120 }), T).high, true);
});

test("a value exactly at the threshold counts as high", () => {
  assert.equal(assessUsage(usage({ cpuPct: 70 }), T).high, true);
  assert.equal(assessUsage(usage({ cpuPct: 69.9 }), T).high, false);
});

test("every metric above its limit is listed as a reason", () => {
  const a = assessUsage(usage({ cpuPct: 95, memPct: 90, netMbps: 10 }), T);
  assert.equal(a.reasons.length, 2);
  assert.match(a.reasons[0], /CPU 95%/);
  assert.match(a.reasons[1], /memory 90%/);
});

test("missing memory data is reported as unknown, not as low and not as high", () => {
  const a = assessUsage(usage({ cpuPct: 5, netMbps: 1 }), T);
  assert.equal(a.high, false);
  assert.deepEqual(a.unknown, ["memory"]);
});

test("if CloudWatch cannot be read, the guard fails safe and warns", () => {
  const a = assessUsage(usage({ readError: "AccessDeniedException" }), T);
  assert.equal(a.high, true);
  assert.match(a.reasons[0], /could not be verified/);
});

test("thresholds come from the environment, with safe fallbacks", () => {
  assert.deepEqual(thresholdsFromEnv({}), T);
  assert.deepEqual(
    thresholdsFromEnv({ USAGE_CPU_PCT: "50", USAGE_MEM_PCT: "90", USAGE_NET_MBPS: "5" }),
    { cpuPct: 50, memPct: 90, netMbps: 5 },
  );
  // Nonsense values fall back to defaults instead of disabling the guard.
  assert.deepEqual(
    thresholdsFromEnv({ USAGE_CPU_PCT: "abc", USAGE_MEM_PCT: "-1", USAGE_NET_MBPS: "" }),
    T,
  );
});

test("phone message names the triggering metrics, the action and the instance", () => {
  const msg = highUsageBindingMessage("ec2:StopInstances", ID, usage({ cpuPct: 92.4, memPct: 10 }), T);
  assert.equal(msg, `HIGH LOAD CPU92 Stop ${ID}`);
});

test("phone message obeys Auth0's 64-character, restricted-character rule", () => {
  const worst = highUsageBindingMessage(
    "ec2:TerminateInstances",
    "i-0123456789abcdef0", // 17 hex, the longest id
    usage({ cpuPct: 100, memPct: 100, netMbps: 123456 }),
    T,
  );
  assert.ok(worst.length <= 64, `${worst.length}: ${worst}`);
  assert.ok(worst.endsWith("Terminate i-0123456789abcdef0"), worst);
  assert.match(worst, /^[A-Za-z0-9\s+\-_.,:#]+$/);
});

test("phone message says UNVERIFIED when usage could not be read", () => {
  const msg = highUsageBindingMessage("ec2:RebootInstances", ID, usage({ readError: "x" }), T);
  assert.equal(msg, `USAGE UNVERIFIED Reboot ${ID}`);
});

test("start is not guarded (nothing runs on a stopped instance)", () => {
  assert.equal(GUARDED_ACTIONS.has("ec2:StartInstances"), false);
  assert.equal(GUARDED_ACTIONS.has("ec2:TerminateInstances"), true);
});
