// Resource-usage guard: decides whether a destructive action needs a second,
// explicit confirmation because the instance looks busy.
//
// An instance can be on the allowlist and still be running something that
// matters right now. If CPU, memory or network usage is above a threshold,
// the approver is warned ("potentially critical workload may be running")
// and asked to confirm a second time before any credential is minted.
//
// This file holds only the decision logic, with no AWS calls, so it can be unit
// tested. Reading the numbers from CloudWatch lives in ./metrics.ts.

/** Actions that interrupt whatever is running on the instance. */
export const GUARDED_ACTIONS: ReadonlySet<string> = new Set([
  "ec2:StopInstances",
  "ec2:TerminateInstances",
  "ec2:RebootInstances",
]);

/** Peak readings over the look-back window. `null` means no data. */
export interface Usage {
  cpuPct: number | null;
  memPct: number | null;
  netMbps: number | null;
  windowMinutes: number;
  /** Set when CloudWatch could not be read at all. */
  readError?: string;
}

export interface Thresholds {
  cpuPct: number;
  memPct: number;
  netMbps: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = { cpuPct: 70, memPct: 80, netMbps: 50 };

export interface Assessment {
  /** True means: warn the approver and require a second confirmation. */
  high: boolean;
  /** Human-readable reasons, e.g. "CPU 92% (limit 70%)". */
  reasons: string[];
  /** Metrics with no data. Reported, but on their own they do not trigger. */
  unknown: string[];
}

/** USAGE_CPU_PCT, USAGE_MEM_PCT, USAGE_NET_MBPS override the defaults. */
export function thresholdsFromEnv(env: NodeJS.ProcessEnv = process.env): Thresholds {
  return {
    cpuPct: positiveNumber(env.USAGE_CPU_PCT, DEFAULT_THRESHOLDS.cpuPct),
    memPct: positiveNumber(env.USAGE_MEM_PCT, DEFAULT_THRESHOLDS.memPct),
    netMbps: positiveNumber(env.USAGE_NET_MBPS, DEFAULT_THRESHOLDS.netMbps),
  };
}

export function assessUsage(usage: Usage, t: Thresholds): Assessment {
  // Fail safe: if we could not look, we cannot say it is idle.
  if (usage.readError) {
    return {
      high: true,
      reasons: [`resource usage could not be verified (${usage.readError})`],
      unknown: ["cpu", "memory", "network"],
    };
  }

  const reasons: string[] = [];
  const unknown: string[] = [];

  check(usage.cpuPct, t.cpuPct, "cpu", (v) => `CPU ${round(v)}% (limit ${t.cpuPct}%)`);
  check(usage.memPct, t.memPct, "memory", (v) => `memory ${round(v)}% (limit ${t.memPct}%)`);
  check(usage.netMbps, t.netMbps, "network", (v) => `network ${round(v)} Mbit/s (limit ${t.netMbps} Mbit/s)`);

  return { high: reasons.length > 0, reasons, unknown };

  function check(value: number | null, limit: number, name: string, describe: (v: number) => string) {
    if (value === null) unknown.push(name);
    else if (value >= limit) reasons.push(describe(value));
  }
}

/**
 * Text shown on the phone for the second confirmation.
 *
 * Auth0 caps binding_message at 64 characters and accepts only letters, digits,
 * whitespace and + - _ . , : #. So no "%" sign. The instance id always fits:
 * the longest form, "HIGH LOAD CPU100 MEM100 NET99999 Terminate i-<17 hex>",
 * is 62 characters.
 */
export function highUsageBindingMessage(
  action: string,
  instanceId: string,
  usage: Usage,
  t: Thresholds,
): string {
  const verb = action.replace(/^ec2:/, "").replace(/Instances$/, "");
  let head: string;
  if (usage.readError) {
    head = "USAGE UNVERIFIED";
  } else {
    const parts: string[] = [];
    if (usage.cpuPct !== null && usage.cpuPct >= t.cpuPct) parts.push(`CPU${clamp(usage.cpuPct, 100)}`);
    if (usage.memPct !== null && usage.memPct >= t.memPct) parts.push(`MEM${clamp(usage.memPct, 100)}`);
    if (usage.netMbps !== null && usage.netMbps >= t.netMbps) parts.push(`NET${clamp(usage.netMbps, 99999)}`);
    head = ["HIGH LOAD", ...parts].join(" ");
  }
  return `${head} ${verb} ${instanceId}`.replace(/[^A-Za-z0-9\s+\-_.,:#]/g, "").slice(0, 64);
}

function positiveNumber(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return raw !== undefined && raw.trim() !== "" && Number.isFinite(n) && n > 0 ? n : fallback;
}

function round(v: number): number {
  return Math.round(v * 10) / 10;
}

function clamp(v: number, max: number): number {
  return Math.min(Math.round(v), max);
}
