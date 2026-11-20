// host/bridge against the fake target (CI, no QNX). The real end-to-end run
// against QNX is tests/target/bridge.sh.
import assert from "node:assert/strict";
import net from "node:net";
import { after, before, test } from "node:test";
import { WebSocket } from "ws";

import { Bridge } from "../src/bridge.ts";
import { GatewayConnection, lineReader, oneShot, type GwMsg } from "../src/gateway.ts";
import { FakeTarget } from "./fake-target.ts";

let target: FakeTarget;
let bridge: Bridge;
let base: string;
let ws: WebSocket;
const wsMsgs: Record<string, unknown>[] = [];

function until<T>(f: () => T | undefined | false, ms = 3000): Promise<T> {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      const v = f();
      if (v) return resolve(v);
      if (Date.now() - t0 > ms) return reject(new Error("condition not met in time"));
      setTimeout(tick, 20);
    };
    tick();
  });
}
async function post(p: string, body: unknown): Promise<{ messages: GwMsg[] }> {
  const r = await fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return (await r.json()) as { messages: GwMsg[] };
}

before(async () => {
  target = await new FakeTarget().start();
  bridge = new Bridge({ target: "127.0.0.1", ports: target.ports, listen: { host: "127.0.0.1", port: 0 }, telemetryHz: 50, log: () => {} });
  const { port } = await bridge.start();
  base = `http://127.0.0.1:${port}`;
  await until(() => Object.values(bridge.gw).every((g) => g.up));
  ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  ws.on("message", (d) => wsMsgs.push(JSON.parse(String(d))));
  await until(() => wsMsgs.length > 0);
});

after(async () => {
  ws.close();
  await bridge.stop();
  await target.stop();
});

test("dashboard gets a snapshot, then live telemetry and gateway state", async () => {
  const snap = wsMsgs[0] as { type: string; gateways: Record<string, { up: boolean }> };
  assert.equal(snap.type, "snapshot");
  for (const role of ["agent", "hmi", "observer", "world"]) assert.equal(snap.gateways[role].up, true, role);
  await until(() => wsMsgs.filter((m) => m.type === "telemetry").length >= 3);
  const health = await (await fetch(base + "/api/health")).json();
  assert.equal(health.agent.hello.role, "agent");
  assert.equal(health.agent.hello.fake, true);
});

test("propose + exec over REST: decision, execution, both in the feed", async () => {
  const { messages } = await post("/api/propose", { action: "body.door.unlock", params: { door: "front_left" }, actor: "agent:test", exec: true });
  assert.deepEqual(messages.map((m) => m.kind), ["decision", "execution"]);
  assert.equal(messages[0].verdict, "ALLOW");
  assert.equal(messages[1].result, "EXECUTED");
  const feed = bridge.feed.slice(-2).map((e) => e.msg.kind);
  assert.deepEqual(feed, ["decision", "execution"]);
  await until(() => wsMsgs.some((m) => m.type === "feed" && (m.event as { msg: GwMsg }).msg.kind === "execution"));
  // the grant id can be presented again; the target refuses the replay
  const again = await post("/api/execute", { grant_id: messages[0].grant_id });
  assert.equal(again.messages[0].result, "REFUSED");
  assert.equal(again.messages[0].reason, "GRANT_SPENT");
});

test("escalation: agent awaits, the dashboard is pushed the escalation and approves over WebSocket", async () => {
  const pending = post("/api/propose", { action: "ota.ecu.flash", params: { ecu: "brake" }, exec: true, await: true });
  const esc = await until(() => wsMsgs.find((m) => m.type === "escalations" && (m.items as unknown[]).length > 0)) as { items: { escalation_id: number }[] };
  const id = esc.items[0].escalation_id;
  ws.send(JSON.stringify({ type: "resolve", ref: "r1", escalation_id: id, approve: true }));
  const reply = await until(() => wsMsgs.find((m) => m.type === "reply" && m.ref === "r1")) as { ok: boolean };
  assert.equal(reply.ok, true);
  const { messages } = await pending;
  assert.deepEqual(messages.map((m) => [m.kind, m.verdict ?? m.result]), [["decision", "ESCALATE"], ["resolution", "ALLOW"], ["execution", "EXECUTED"]]);
  assert.equal(messages[0].done, false);
  await until(() => bridge.escalations.length === 0);
});

test("world scenario changes the verdict; errors are returned, not thrown", async () => {
  await post("/api/sim", { cmd: "scenario highway" });
  const { messages } = await post("/api/propose", { action: "ota.ecu.flash", params: { ecu: "brake" } });
  assert.equal(messages[0].verdict, "BLOCK");
  assert.equal(messages[0].reason, "R156_NOT_SAFE_STATE");
  await post("/api/sim", { cmd: "scenario park" });
  const r = await post("/api/resolve", { escalation_id: 999, approve: true });
  assert.equal(r.messages[0].kind, "error");
  const bad = await fetch(base + "/api/propose", { method: "POST", body: "[]" });
  assert.equal(bad.status, 400);
});

test("notes from the agent reach the feed", async () => {
  await post("/api/note", { source: "agent", text: "I will propose a door unlock" });
  const last = bridge.feed[bridge.feed.length - 1];
  assert.equal(last.msg.kind, "note");
  assert.equal(last.msg.text, "I will propose a door unlock");
});

test("authority up/down follows the observer's stats stream (fail-closed banner)", async () => {
  await until(() => bridge.authority.up === true);
  target.authorityDown = true;
  await until(() => wsMsgs.some((m) => m.type === "authority" && m.up === false));
  assert.equal(bridge.authority.up, false);
  target.authorityDown = false;
  await until(() => bridge.authority.up === true);
  assert.equal((bridge.snapshot().authority as { up: boolean }).up, true);
});

test("gateway client: reconnects, splits lines, rejects pending requests on loss", async () => {
  const got: GwMsg[] = [];
  const feed = lineReader((m) => got.push(m), () => got.push({ kind: "BAD" }));
  feed(Buffer.from('{"kind":"a","done":true}\n{"kind":'));
  feed(Buffer.from('"b"}\nnot json\n\n'));
  assert.deepEqual(got.map((m) => m.kind), ["a", "b", "BAD"]);

  // a server that answers hello, then drops the connection on the first request
  let conns = 0;
  const srv = net.createServer((s) => {
    conns++;
    s.on("data", lineReader((m) => {
      if (m.op === "hello") s.write(JSON.stringify({ kind: "hello", id: m.id, role: "agent", done: true }) + "\n");
      else s.destroy();
    }, () => {}, false));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as net.AddressInfo).port;
  const c = new GatewayConnection("agent", "127.0.0.1", port, { retryMs: 50 }).start();
  await until(() => c.up);
  await assert.rejects(c.request({ op: "state" }), /connection lost/);
  await until(() => c.up && conns >= 2);
  c.stop();
  srv.close();
  await assert.rejects(oneShot("127.0.0.1", port, { op: "state" }, { timeoutMs: 500 }));
});
