#!/usr/bin/env node
//
// The agent's only way in. Every capability is a subcommand with validated
// arguments — nothing here builds a shell string or evaluates input, so a
// model that has been fed a hostile log line still cannot reach anything
// beyond these verbs.
//
// Reads run on the agent's own read-only credentials. Writes never do: the
// broker asks a human on their phone, and only an approval yields a session
// credential scoped to that one action on that one instance.

import { monitorInstances, executeAction, type WriteAction } from "./aws/ec2";
import { requestAction, type BrokerOutcome } from "./broker/client";

const INSTANCE_ID = /^i-[0-9a-f]{8,17}$/;

// Audit label the broker stores with the plan. Not an identity: the broker
// decides who approves from its own configuration.
const REQUESTED_BY = process.env.CLAWOPS_REQUESTED_BY || "nanoclaw-agent";

const WRITE_VERBS = {
  stop:   { action: "ec2:StopInstances",   message: "Stop initiated" },
  start:  { action: "ec2:StartInstances",  message: "Start initiated" },
  reboot: { action: "ec2:RebootInstances", message: "Reboot initiated" },
} as const satisfies Record<string, { action: WriteAction; message: string }>;

type WriteVerb = keyof typeof WRITE_VERBS;

function isWriteVerb(x: string | undefined): x is WriteVerb {
  return x !== undefined && Object.prototype.hasOwnProperty.call(WRITE_VERBS, x);
}

const USAGE = `clawops <command>

  monitor                      Health report for every instance in the region
  stop    <id> <reason...>     Stop an instance             (phone approval)
  start   <id> <reason...>     Start a stopped instance     (phone approval)
  reboot  <id> <reason...>     Restart an instance          (phone approval)

Instance ids look like i-0a3f9c21b7e4d500. The reason is required: it is what
the approver reads, and what the audit record keeps.`;

// Three exits, three meanings: 0 done, 1 you asked wrong, 2 the system said no.
function fail(message: string): never {
  console.error(JSON.stringify({ ok: false, error: message }, null, 2));
  process.exit(1);
}

function refuse(payload: object): never {
  console.error(JSON.stringify({ ok: false, ...payload }, null, 2));
  process.exit(2);
}

function emit(payload: object): void {
  console.log(JSON.stringify({ ok: true, ...payload }, null, 2));
}

function instanceIdOrDie(raw: string | undefined): string {
  if (!raw) fail("An instance id is required, e.g. i-0a3f9c21b7e4d500");
  if (!INSTANCE_ID.test(raw))
    fail(`Not a valid instance id: ${JSON.stringify(raw)}. Expected i- followed by 8-17 hex characters.`);
  return raw;
}

function reasonOrDie(words: string[]): string {
  const reason = words.join(" ").trim();
  if (!reason)
    fail("A reason is required after the instance id. It is shown to the approver and kept in the audit record.");
  return reason;
}

const REFUSALS = {
  denied:  "The approver declined this action on their phone. Nothing was changed.",
  expired: "Nobody answered the approval request in time. Nothing was changed.",
  busy:    "Another approval is already waiting on the approver. Try again once it is decided.",
} as const;

async function write(verb: WriteVerb, instanceId: string, reason: string): Promise<void> {
  const { action, message } = WRITE_VERBS[verb];

  const outcome: BrokerOutcome = await requestAction({
    action,
    instanceId,
    reason,
    requestedBy: REQUESTED_BY,
  });

  if (outcome.status !== "approved") {
    const detail =
      outcome.status === "rejected" || outcome.status === "error"
        ? outcome.error
        : REFUSALS[outcome.status];
    refuse({ error: outcome.status, detail });
  }

  const result = await executeAction(action, instanceId, outcome.credentials);

  emit({
    message: `${message} for ${instanceId}`,
    instanceId,
    previousState: result.previousState,
    currentState: result.currentState,
    approvedBy: outcome.approvedBy,
    planId: outcome.planId,
    credentialExpiresAt: outcome.expiresAt,
  });
}

async function main(): Promise<void> {
  const [command, id, ...rest] = process.argv.slice(2);

  if (command === "monitor") {
    emit(await monitorInstances());
    return;
  }

  if (isWriteVerb(command)) {
    await write(command, instanceIdOrDie(id), reasonOrDie(rest));
    return;
  }

  if (command === undefined || command === "help" || command === "--help") {
    console.log(USAGE);
    return;
  }

  fail(`Unknown command: ${JSON.stringify(command)}\n\n${USAGE}`);
}

main().catch((err: unknown) => {
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string } };

  // AWS refusals are expected and meaningful — surface them as data, not a crash.
  if (e.name === "UnauthorizedOperation" || e.name === "AccessDenied" || e.name === "AccessDeniedException") {
    refuse({
      error: "AccessDenied",
      detail: e.message,
      hint: "The approved credential does not cover this instance. Only instances tagged ManagedBy=ClawOps can be changed.",
    });
  }

  // Never let a wrapper message hide the real reason underneath it.
  const cause = e.cause?.code ?? e.cause?.message;
  fail(cause ? `${e.message} (${cause})` : (e.message ?? String(err)));
});
