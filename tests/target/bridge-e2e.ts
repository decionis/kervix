// host/bridge against the REAL QNX target (gateways forwarded to 127.0.0.1:7301-7304).
// Run by tests/target/bridge.sh. Prints PASS/FAIL lines like the other target tests.
import { WebSocket } from "ws";
import { Bridge } from "../../host/bridge/src/bridge.ts";
import type { GwMsg } from "../../host/bridge/src/gateway.ts";

let fail = 0;
const pass = (s: string) => console.log(`PASS  ${s}`);
const bad = (s: string) => { console.log(`FAIL  ${s}`); fail = 1; };
const until = async <T>(f: () => T | undefined | false, ms = 15000): Promise<T | undefined> => {
  const t0 = Date.now();
  for (;;) { const v = f(); if (v) return v; if (Date.now() - t0 > ms) return undefined; await new Promise((r) => setTimeout(r, 50)); }
};

const b = new Bridge({ target: process.env.KX_TARGET ?? "127.0.0.1", listen: { host: "127.0.0.1", port: 0 }, telemetryHz: 20, log: () => {} });
const { port } = await b.start();
const base = `http://127.0.0.1:${port}`;
const post = async (p: string, body: unknown) => ((await (await fetch(base + p, { method: "POST", body: JSON.stringify(body) })).json()) as { messages: GwMsg[] }).messages;

(await until(() => Object.values(b.gw).every((g) => g.up))) ? pass("bridge connected to all four QNX gateways") : bad("gateways not up");
const types = Object.fromEntries(Object.entries(b.gw).map(([r, g]) => [r, g.hello?.type]));
JSON.stringify(types) === JSON.stringify({ agent: "agentgw_t", hmi: "hmigw_t", observer: "obsgw_t", world: "worldgw_t" }) && !b.gw.agent.hello?.fake
  ? pass(`real target, typed gateways: ${JSON.stringify(types)}`) : bad(`types ${JSON.stringify(types)}`);

const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
const wsm: Record<string, unknown>[] = [];
ws.on("message", (d) => wsm.push(JSON.parse(String(d))));
const tel = await until(() => wsm.filter((m) => m.type === "telemetry").length >= 10 && wsm);
tel && wsm[0].type === "snapshot" ? pass("dashboard WebSocket: snapshot then live telemetry from the observer gateway") : bad("ws telemetry");
(await until(() => b.stats.length > 0 && b.stats[0].startsWith("kervixd"))) ? pass(`stats stream: ${b.stats[0]}`) : bad("stats");

await post("/api/sim", { cmd: "scenario park" });
let ok = false;
for (let i = 0; i < 40 && !ok; i++) {
  const t = (b.telemetry?.telemetry ?? {}) as Record<string, number>;
  ok = t.speed_dkph === 0 && t.gear === 0 && t.park_brake === 1;
  if (!ok) await new Promise((r) => setTimeout(r, 500));
}
ok ? pass("world gateway: parked") : bad("could not park");

let m = await post("/api/propose", { action: "body.door.unlock", params: { door: "rear_right" }, actor: "agent:bridge-e2e", exec: true });
m.map((x) => x.kind).join() === "decision,execution" && m[0].verdict === "ALLOW" && m[1].result === "EXECUTED"
  ? pass("REST propose: ALLOW -> EXECUTED on QNX") : bad(`propose ${JSON.stringify(m)}`);
const again = await post("/api/execute", { grant_id: m[0].grant_id });
again[0]?.reason === "GRANT_SPENT" ? pass("REST execute of a spent grant: refused by kervixd (GRANT_SPENT)") : bad(`replay ${JSON.stringify(again)}`);

const D = "sha256:" + "01".repeat(32);
const pending = post("/api/propose", { action: "ota.ecu.flash", params: { ecu: "bms", image_digest: D }, exec: true, await: true });
const esc = (await until(() => wsm.find((x) => x.type === "escalations" && (x.items as unknown[]).length > 0))) as { items: { escalation_id: number; intent: { action: string } }[] } | undefined;
esc?.items[0].intent.action === "ota.ecu.flash" ? pass(`dashboard pushed escalation #${esc.items[0].escalation_id} (ota.ecu.flash)`) : bad("no escalation push");
ws.send(JSON.stringify({ type: "resolve", ref: "r", escalation_id: esc?.items[0].escalation_id ?? 0, approve: true, approver: "hmi:bridge-e2e" }));
m = await pending;
m.map((x) => `${x.kind}:${x.verdict ?? x.result}`).join() === "decision:ESCALATE,resolution:ALLOW,execution:EXECUTED"
  ? pass("driver approves from the dashboard -> agent's awaiting proposal executes") : bad(`await ${JSON.stringify(m)}`);
const kinds = b.feed.map((e) => e.msg.kind);
kinds.includes("resolved") && kinds.filter((k) => k === "execution").length >= 3 ? pass(`feed recorded ${b.feed.length} events`) : bad(`feed ${kinds}`);

// ledger explorer: the vehicle's signed ledger, mirrored through the observer gateway and verified
await b.syncLedger();
const li = b.ledger.info;
li.records > 5 && li.first_seq === 1 && li.last_seq === li.records && /^[A-Za-z0-9_-]{43}$/.test(String(li.kid))
  ? pass(`ledger mirrored from the vehicle: ${li.records} signed capsules, key ${String(li.kid).slice(0, 12)}…`) : bad(`ledger info ${JSON.stringify(li)}`);
const v = await (await fetch(base + "/api/verify", { method: "POST", body: "{}" })).json();
v.verified && v.replay.match >= 3 && v.findings.length === 0
  ? pass(`Verify button: VERIFIED (signatures, chain, replay ${v.replay.match}/${v.replay.match}) in ${v.elapsed_ms} ms`) : bad(`verify ${JSON.stringify(v.findings)}`);
const t = await (await fetch(base + "/api/verify", { method: "POST", body: JSON.stringify({ tamper_seq: 3 }) })).json();
!t.verified && t.findings.length > 0 && t.findings.every((f: { where: string }) => f.where === "capsule #3")
  ? pass("one record back-dated by a few ms: NOT VERIFIED, caught exactly at capsule #3") : bad(`tamper ${JSON.stringify(t.findings)}`);

ws.close();
await b.stop();
console.log(fail ? "BRIDGE RESULT: FAIL" : "BRIDGE RESULT: PASS");
process.exit(fail);
