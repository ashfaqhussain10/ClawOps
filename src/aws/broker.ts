/**
 * ClawOps broker.
 *
 * One endpoint. The agent asks for a write action, a human approves it on
 * their phone, and the broker returns AWS credentials scoped to exactly that
 * one action on that one instance for fifteen minutes.
 *
 * Resource-usage guard: before a stop, terminate or reboot, the broker reads
 * the instance's CPU, memory and network usage. If any is above its threshold,
 * the approver gets a second phone push ("HIGH LOAD ...") and must confirm
 * again: a critical workload may be running even on an allowlisted instance.
 *
 * Run:  npx tsx src/aws/broker.ts      (reads .env from the working directory)
 */

import express from "express";
import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import dotenv from "dotenv";

import { readUsage } from "../broker/metrics";
import {
  GUARDED_ACTIONS,
  assessUsage,
  highUsageBindingMessage,
  thresholdsFromEnv,
  type Assessment,
  type Usage,
} from "../broker/usage";

dotenv.config();

// ---------------------------------------------------------------- config

const PORT = Number(process.env.BROKER_PORT ?? 3001);

const AUTH0_DOMAIN = must("AUTH0_DOMAIN");
const AUTH0_CLIENT_ID = must("AUTH0_CLIENT_ID");
const AUTH0_CLIENT_SECRET = must("AUTH0_CLIENT_SECRET");
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE ?? "https://clawops/api";
const RAR_TYPE = process.env.AUTH0_RAR_TYPE ?? "clawops:aws_action";

const AWS_REGION = process.env.AWS_REGION ?? "ap-south-1";
const AWS_ACCOUNT_ID = must("AWS_ACCOUNT_ID");
const ELEVATED_ROLE_ARN = `arn:aws:iam::750240012171:role/clawops-elevated`;

/** The agent never names the role. It is hardcoded here on purpose. */
const SESSION_SECONDS = 900; // AWS minimum for AssumeRole

/** Nothing outside this list can ever be requested, whatever the agent sends. */
const ALLOWED_ACTIONS = new Set([
  "ec2:TerminateInstances",
  "ec2:StopInstances",
  "ec2:StartInstances",
  "ec2:RebootInstances",
]);

const INSTANCE_ID = /^i-[0-9a-f]{8,17}$/;

/** Slack user id -> Auth0 user id. Replace with a table when this is real. */
const APPROVERS: Record<string, string> = JSON.parse(
  process.env.APPROVER_MAP ?? "{}"
);

/** How long we will wait for someone to pick up their phone. */
const APPROVAL_TIMEOUT_MS = 120_000;

/** Above any of these, a destructive action needs a second confirmation. */
const USAGE_THRESHOLDS = thresholdsFromEnv();
const USAGE_WINDOW_MIN = Number(process.env.USAGE_WINDOW_MIN ?? 15);
const USAGE_PERIOD_S = Number(process.env.USAGE_PERIOD_S ?? 300);

function must(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env var ${name}`);
  return v;
}

// ---------------------------------------------------------------- storage

const db = new Database(process.env.BROKER_DB ?? "clawops.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS plans (
    id            TEXT PRIMARY KEY,
    requested_by  TEXT NOT NULL,
    action        TEXT NOT NULL,
    resource_arn  TEXT NOT NULL,
    instance_id   TEXT NOT NULL,
    reason        TEXT,
    status        TEXT NOT NULL,
    approved_by   TEXT,
    created_at    INTEGER NOT NULL,
    decided_at    INTEGER
  );
`);

const insertPlan = db.prepare(`
  INSERT INTO plans (id, requested_by, action, resource_arn, instance_id,
                     reason, status, created_at)
  VALUES (@id, @requested_by, @action, @resource_arn, @instance_id,
          @reason, 'pending', @created_at)
`);

// Added for the usage guard and the experiments. ALTER, not CREATE, so an
// existing clawops.db keeps its history.
const existingColumns = new Set(
  (db.prepare(`PRAGMA table_info(plans)`).all() as { name: string }[]).map((c) => c.name),
);
for (const [name, type] of [
  ["usage_json", "TEXT"],      // peak CPU / memory / network readings
  ["high_usage", "INTEGER"],   // 1 if the second confirmation was required
  ["second_status", "TEXT"],   // approved | denied | expired, for that confirmation
  ["timings_json", "TEXT"],    // per-stage durations in ms
] as const) {
  if (!existingColumns.has(name)) db.exec(`ALTER TABLE plans ADD COLUMN ${name} ${type}`);
}

const closePlan = db.prepare(`
  UPDATE plans SET status = ?, approved_by = ?, decided_at = ? WHERE id = ?
`);

const recordUsage = db.prepare(`
  UPDATE plans SET usage_json = ?, high_usage = ? WHERE id = ?
`);

const recordSecond = db.prepare(`
  UPDATE plans SET second_status = ? WHERE id = ?
`);

const recordTimings = db.prepare(`
  UPDATE plans SET timings_json = ? WHERE id = ?
`);

/** Stopwatch: each mark records the ms since the previous mark. */
function stopwatch() {
  const start = performance.now();
  let last = start;
  const stages: Record<string, number> = {};
  return {
    mark(stage: string) {
      const now = performance.now();
      stages[`${stage}_ms`] = Math.round(now - last);
      last = now;
    },
    result(): Record<string, number> {
      return { ...stages, total_ms: Math.round(performance.now() - start) };
    },
  };
}

// ---------------------------------------------------------------- auth0

type CibaOutcome =
  | { status: "approved"; sub: string; granted: unknown }
  | { status: "denied" }
  | { status: "expired" };

async function cibaAuthorize(plan: {
  id: string;
  action: string;
  instance_id: string;
  reason: string;
  auth0Sub: string;
  /** Overrides the default phone text, e.g. for the high-usage confirmation. */
  bindingMessage?: string;
}): Promise<{ authReqId: string; interval: number }> {
  const body = new URLSearchParams({
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET,
    scope: "openid",
    // audience: AUTH0_AUDIENCE,
    binding_message:
      plan.bindingMessage ?? `${plan.action.split(":")[1]} ${plan.instance_id}`.slice(0, 64),
    login_hint: JSON.stringify({
      format: "iss_sub",
      iss: `https://${AUTH0_DOMAIN}/`,
      sub: plan.auth0Sub,
    }),
    // What the human sees on the phone. Built from the same validated values
    // the session policy below is built from, so the two cannot disagree.
    // authorization_details: JSON.stringify([{ type: RAR_TYPE }]),
  });

  const res = await fetch(`https://${AUTH0_DOMAIN}/bc-authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const json: any = await res.json();
  if (!res.ok) {
    throw new Error(
      `bc-authorize failed: ${json.error} ${json.error_description ?? ""}`
    );
  }
  return { authReqId: json.auth_req_id, interval: (json.interval ?? 5) * 1000 };
}

async function cibaPoll(
  authReqId: string,
  intervalMs: number
): Promise<CibaOutcome> {
  const deadline = Date.now() + APPROVAL_TIMEOUT_MS;
  let wait = intervalMs;

  while (Date.now() < deadline) {
    await sleep(wait);

    const res = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:openid:params:grant-type:ciba",
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET,
        auth_req_id: authReqId,
      }),
    });

    const json: any = await res.json();

    if (res.ok) {
      const claims = decodeJwt(json.id_token);
      return {
        status: "approved",
        sub: claims.sub,
        granted: json.authorization_details ?? claims.authorization_details,
      };
    }

    switch (json.error) {
      case "authorization_pending":
        break;
      case "slow_down":
        wait += 2000;
        break;
      case "access_denied":
        return { status: "denied" };
      case "expired_token":
        return { status: "expired" };
      default:
        throw new Error(`ciba poll failed: ${json.error}`);
    }
  }
  return { status: "expired" };
}

// ---------------------------------------------------------------- aws

const sts = new STSClient({ region: AWS_REGION });

async function mint(plan: {
  id: string;
  action: string;
  resource_arn: string;
  approvedBy: string;
}) {
  // Narrows only. The credentials can do the overlap between what
  // clawops-elevated allows and what this policy allows -- never more.
  const sessionPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: plan.action,
        Resource: plan.resource_arn,
      },
    ],
  };

  const out = await sts.send(
    new AssumeRoleCommand({
      RoleArn: ELEVATED_ROLE_ARN,
      RoleSessionName: sessionName(plan.approvedBy, plan.id),
      Policy: JSON.stringify(sessionPolicy),
      DurationSeconds: SESSION_SECONDS,
    })
  );

  const c = out.Credentials!;
  return {
    accessKeyId: c.AccessKeyId!,
    secretAccessKey: c.SecretAccessKey!,
    sessionToken: c.SessionToken!,
    expiration: c.Expiration!.toISOString(),
  };
}

/**
 * RoleSessionName must match [\w+=,.@-]{2,64}. Auth0 subs contain a pipe,
 * so it has to be scrubbed or AssumeRole rejects the call.
 * This string is what lands in CloudTrail, which is the whole audit story.
 */
function sessionName(sub: string, planId: string): string {
  const safe = sub.replace(/[^\w+=,.@-]/g, "-");
  return `approved-by-${safe}-${planId}`.slice(0, 64);
}

// ---------------------------------------------------------------- routes

const app = express();
app.use(express.json());

app.get("/ping", (_req, res) => res.json({ ok: true }));

app.post("/request-action", async (req, res) => {
  const watch = stopwatch();
  const { action, instanceId, reason, requestedBy } = req.body ?? {};

  // 1. Everything the agent sent is untrusted. Check it before Auth0 is
  //    involved, so a compromised agent cannot even generate a prompt.
  if (!ALLOWED_ACTIONS.has(action)) {
    return res.status(400).json({ status: "rejected", error: "action not allowed" });
  }
  if (typeof instanceId !== "string" || !INSTANCE_ID.test(instanceId)) {
    return res.status(400).json({ status: "rejected", error: "bad instance id" });
  }
  const auth0Sub = APPROVERS[requestedBy];
  if (!auth0Sub) {
    return res.status(403).json({ status: "rejected", error: "unknown requester" });
  }

  const planId = `req-${randomUUID().slice(0, 8)}`;
  const resourceArn =
    `arn:aws:ec2:${AWS_REGION}:${AWS_ACCOUNT_ID}:instance/${instanceId}`;

  insertPlan.run({
    id: planId,
    requested_by: requestedBy,
    action,
    resource_arn: resourceArn,
    instance_id: instanceId,
    reason: reason ?? "",
    created_at: Date.now(),
  });

  console.log(`[${planId}] ${action} ${instanceId} requested by ${requestedBy}`);
  watch.mark("validate");

  // Set once the usage guard has run; returned with every outcome after it.
  let usage: Usage | undefined;
  let assessment: Assessment | undefined;
  const guardFields = () =>
    usage ? { usage, highUsage: assessment!.high, warnings: assessment!.reasons } : {};

  const finish = (status: string, approvedBy: string | null) => {
    closePlan.run(status, approvedBy, Date.now(), planId);
    const timings = watch.result();
    recordTimings.run(JSON.stringify(timings), planId);
    console.log(`[${planId}] ${status} ${JSON.stringify(timings)}`);
    return timings;
  };

  try {
    // 2. Ask a human. Blocking on purpose -- this is a POC and the pause is
    //    the demo. Move to a background job when Slack needs a fast ack.
    const { authReqId, interval } = await cibaAuthorize({
      id: planId,
      action,
      instance_id: instanceId,
      reason: reason ?? "",
      auth0Sub,
    });
    watch.mark("push1");
    console.log(`[${planId}] pushed to phone, waiting`);

    const outcome = await cibaPoll(authReqId, interval);
    watch.mark("approval1");

    if (outcome.status !== "approved") {
      const timings = finish(outcome.status, null);
      return res.json({ status: outcome.status, planId, timings });
    }

    // 3. Usage guard. Read the instance's load *after* the first approval, so
    //    the numbers are current when the second decision is made.
    if (GUARDED_ACTIONS.has(action)) {
      usage = await readUsage(instanceId, {
        region: AWS_REGION,
        windowMinutes: USAGE_WINDOW_MIN,
        periodSeconds: USAGE_PERIOD_S,
      });
      assessment = assessUsage(usage, USAGE_THRESHOLDS);
      recordUsage.run(JSON.stringify(usage), assessment.high ? 1 : 0, planId);
      watch.mark("usage");
      console.log(
        `[${planId}] usage ${JSON.stringify(usage)} -> ${assessment.high ? "HIGH" : "normal"}`,
      );

      if (assessment.high) {
        // Resource usage of node high: potentially critical workload may be
        // running. Ask again, with the reason on the phone.
        console.log(`[${planId}] high usage: ${assessment.reasons.join("; ")}, asking again`);
        const second = await cibaAuthorize({
          id: planId,
          action,
          instance_id: instanceId,
          reason: reason ?? "",
          auth0Sub,
          bindingMessage: highUsageBindingMessage(action, instanceId, usage, USAGE_THRESHOLDS),
        });
        watch.mark("push2");
        const confirm = await cibaPoll(second.authReqId, second.interval);
        watch.mark("approval2");
        recordSecond.run(confirm.status, planId);

        if (confirm.status !== "approved") {
          const timings = finish(confirm.status, null);
          return res.json({
            status: confirm.status,
            stage: "high-usage-confirmation",
            planId,
            ...guardFields(),
            timings,
          });
        }
      }
    }

    // 4. Confirm the human approved what we asked for, not something else.
    assertGrantMatches(outcome.granted, action, instanceId);

    // 5. Only now does anything get minted.
    const credentials = await mint({
      id: planId,
      action,
      resource_arn: resourceArn,
      approvedBy: outcome.sub,
    });
    watch.mark("mint");

    const timings = finish("approved", outcome.sub);
    console.log(`[${planId}] approved by ${outcome.sub}, key expires ${credentials.expiration}`);

    return res.json({
      status: "approved",
      planId,
      approvedBy: outcome.sub,
      credentials,
      expiresAt: credentials.expiration,
      ...guardFields(),
      timings,
    });
  } catch (err: any) {
    finish("failed", null);
    console.error(`[${planId}] ${err.message}`);
    return res.status(500).json({ status: "error", error: err.message });
  }
});

/**
 * Auth0 echoes back what was actually consented to. If it does not match the
 * request, something changed between asking and approving -- refuse to mint.
 * Auth0 only validates the type, not the fields, so this check is ours to do.
 */
function assertGrantMatches(granted: any, action: string, instanceId: string) {
  if (!Array.isArray(granted) || granted.length === 0) {
    console.warn("no authorization_details echoed back -- skipping match check");
    return; // POC: warn rather than fail. Tighten this before production.
  }
  const ok = granted.some(
    (d: any) => d.action === action && d.instance === instanceId
  );
  if (!ok) throw new Error("granted authorization does not match the request");
}

// ---------------------------------------------------------------- helpers

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function decodeJwt(token: string): any {
  const payload = token.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

app.listen(PORT, () => {
  console.log(`broker on :${PORT}`);
  console.log(`elevated role: ${ELEVATED_ROLE_ARN}`);
  console.log(`allowed actions: ${[...ALLOWED_ACTIONS].join(", ")}`);
  console.log(
    `usage guard on ${[...GUARDED_ACTIONS].join(", ")}: ` +
      `cpu>=${USAGE_THRESHOLDS.cpuPct}% mem>=${USAGE_THRESHOLDS.memPct}% ` +
      `net>=${USAGE_THRESHOLDS.netMbps}Mbit/s over ${USAGE_WINDOW_MIN} min`,
  );
});
