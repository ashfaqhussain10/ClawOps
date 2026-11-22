// Talks to the approval broker running on the host.
//
// The broker call must bypass the egress proxy. NanoClaw starts every agent
// container with HTTP_PROXY / HTTPS_PROXY and NODE_USE_ENV_PROXY=1 supplied by
// OneCLI, so that calls to third-party APIs are routed through its credential
// gateway. The gateway does not forward host-internal traffic: it resets the
// connection (ECONNRESET), and the broker never sees the request.
//
// Since Node 22.21 / 24.5, NODE_USE_ENV_PROXY=1 applies to node:http as well as
// fetch: http.globalAgent is built from the proxy variables at startup, and
// host.docker.internal is not in NO_PROXY. So the request below uses its own
// http.Agent. A fresh agent has no proxy configuration and always connects
// directly. (Verified inside the agent container on Node 22.23.2: the default
// agent gets ECONNRESET, a fresh agent gets 200.) This also keeps the minted
// credentials in the broker's reply from passing through the gateway.

import http from "node:http";
import { URL } from "node:url";

import type { SessionCredentials } from "../types";

/** Direct connections only: never inherits proxy settings from the environment. */
const directAgent = new http.Agent();

export interface ActionRequest {
  action: string;
  instanceId: string;
  reason: string;
  /** Audit label stored with the plan. Not an identity — the broker decides who approves. */
  requestedBy: string;
}

export type BrokerOutcome =
  | {
      status: "approved";
      planId: string;
      approvedBy: string;
      credentials: SessionCredentials;
      expiresAt: string;
      /** Present when the approver confirmed despite high resource usage. */
      warnings?: string[];
    }
  | {
      status: "denied" | "expired" | "busy";
      /** "high-usage-confirmation" when the refusal came at the second push. */
      stage?: string;
      warnings?: string[];
    }
  | { status: "rejected" | "error"; error: string };

export interface BrokerOptions {
  url?: string;
  timeoutMs?: number;
}

/** Where NanoClaw's `--add-host` maps the host. Override for host-side runs. */
export const DEFAULT_BROKER_URL = "http://host.docker.internal:3001";

/**
 * The broker blocks until the approver's phone answers: up to 120 s per push,
 * and two pushes when the usage guard asks for a second confirmation. Allow
 * that plus margin, but never hang forever.
 */
export const DEFAULT_TIMEOUT_MS = 330_000;

export function requestAction(
  input: ActionRequest,
  opts: BrokerOptions = {},
): Promise<BrokerOutcome> {
  const endpoint = new URL(
    "/request-action",
    opts.url ?? process.env.CLAWOPS_BROKER_URL ?? DEFAULT_BROKER_URL,
  );
  const body = Buffer.from(JSON.stringify(input), "utf8");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return new Promise((resolve, reject) => {
    const req = http.request(
      endpoint,
      {
        method: "POST",
        agent: directAgent,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": body.length,
          Accept: "application/json",
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("error", reject);
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: unknown;
          try {
            json = JSON.parse(text);
          } catch (err) {
            reject(
              new Error(`broker returned a non-JSON response (HTTP ${res.statusCode})`, {
                cause: err,
              }),
            );
            return;
          }
          try {
            resolve(parseOutcome(json, res.statusCode ?? 0));
          } catch (err) {
            reject(err);
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error(`broker did not answer within ${timeoutMs / 1000}s`));
    });
    req.on("error", (err) => {
      // Keep the socket-level reason (ECONNREFUSED, ENOTFOUND, ...) attached:
      // the CLI prints it, so a network failure names itself.
      reject(new Error(`could not reach the broker at ${endpoint.origin}`, { cause: err }));
    });
    req.end(body);
  });
}

/**
 * The wire format is loose JSON. Pin it to the union here so the CLI never
 * switches on a field that might be missing.
 */
export function parseOutcome(json: unknown, httpStatus: number): BrokerOutcome {
  const o = (json ?? {}) as Record<string, unknown>;

  switch (o.status) {
    case "approved": {
      const c = o.credentials as Record<string, unknown> | undefined;
      if (
        !c ||
        typeof c.accessKeyId !== "string" ||
        typeof c.secretAccessKey !== "string" ||
        typeof c.sessionToken !== "string"
      ) {
        throw new Error("broker said approved but sent no usable credentials");
      }
      const expiration = String(c.expiration ?? o.expiresAt ?? "");
      return {
        status: "approved",
        planId: String(o.planId ?? ""),
        approvedBy: String(o.approvedBy ?? ""),
        credentials: {
          accessKeyId: c.accessKeyId,
          secretAccessKey: c.secretAccessKey,
          sessionToken: c.sessionToken,
          expiration,
        },
        expiresAt: String(o.expiresAt ?? expiration),
        ...warningsOf(o),
      };
    }
    case "denied":
    case "expired":
    case "busy":
      return {
        status: o.status,
        ...(typeof o.stage === "string" ? { stage: o.stage } : {}),
        ...warningsOf(o),
      };
    case "rejected":
    case "error":
      return { status: o.status, error: String(o.error ?? `HTTP ${httpStatus}`) };
    default:
      throw new Error(
        `broker returned an unknown status ${JSON.stringify(o.status)} (HTTP ${httpStatus})`,
      );
  }
}

/** Keeps the usage-guard warnings only if the broker sent a non-empty list of strings. */
function warningsOf(o: Record<string, unknown>): { warnings?: string[] } {
  const w = o.warnings;
  return Array.isArray(w) && w.length > 0 && w.every((x) => typeof x === "string")
    ? { warnings: w as string[] }
    : {};
}
