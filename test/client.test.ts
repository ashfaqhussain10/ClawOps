import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import type { AddressInfo } from "node:net";

import { parseOutcome } from "../src/broker/client";

test("the broker call bypasses an env-configured proxy (the agent-container ECONNRESET bug)", async () => {
  // Fake broker: answers like the real one.
  const broker = http.createServer((_req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ status: "denied" }));
  });
  // Fake OneCLI gateway: resets every connection, as the real one does for host traffic.
  let proxyHits = 0;
  const proxy = net.createServer((socket) => {
    proxyHits++;
    socket.destroy();
  });
  await new Promise<void>((r) => broker.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", r));
  const brokerUrl = `http://127.0.0.1:${(broker.address() as AddressInfo).port}`;
  const proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;

  // NODE_USE_ENV_PROXY is read at process start, so run the client in a child
  // process with the same environment OneCLI gives the agent container.
  // NO_PROXY is set to something that does NOT cover 127.0.0.1, so the broker
  // address really is eligible for proxying, as host.docker.internal is there.
  const clientPath = path.resolve(__dirname, "../src/broker/client.ts");
  const script = `
    const { requestAction } = require(${JSON.stringify(clientPath)});
    requestAction({ action: "ec2:StopInstances", instanceId: "i-0747af78fd8763865", reason: "t", requestedBy: "t" },
                  { url: ${JSON.stringify(brokerUrl)}, timeoutMs: 5000 })
      .then((o) => console.log(JSON.stringify(o)))
      .catch((e) => console.log(JSON.stringify({ failed: e.message, cause: e.cause && e.cause.code })));
  `;
  const stdout = await new Promise<string>((resolve, reject) =>
    execFile(
      process.execPath,
      ["--import", "tsx", "-e", script],
      {
        env: {
          ...process.env,
          NODE_USE_ENV_PROXY: "1",
          HTTP_PROXY: proxyUrl,
          http_proxy: proxyUrl,
          NO_PROXY: "example.invalid",
          no_proxy: "example.invalid",
        },
      },
      (err, out) => (err ? reject(err) : resolve(out)),
    ),
  );
  broker.close();
  proxy.close();

  assert.deepEqual(JSON.parse(stdout.trim().split("\n").pop()!), { status: "denied" });
  assert.equal(proxyHits, 0, "the broker call must never touch the proxy");
});

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
