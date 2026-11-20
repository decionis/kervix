import assert from "node:assert/strict";
import { test } from "node:test";

import { denseHistogram, initialState, lastDecision, parseStats, reduce } from "../src/model.ts";

// verbatim kervixd stats text, as the observer gateway sends it
const STATS = [
  "kervixd  uptime 42 s  policy kervix-default v1.0.0  hash 8539d711...",
  "telemetry seq 4100  age 3.1 ms",
  "proposals 12  ALLOW 7  ESCALATE 2  BLOCK 3",
  "  reason OK                       7",
  "PROPOSE latency (in-server): min 812.4 us  max 9120.0 us",
  "  p50 < 2048 us   p99 < 16384 us   (log2 buckets)",
  "  [   512,   1024) us  3",
  "  [  1024,   2048) us  5",
  "  [  4096,   8192) us  3",
  "  [  8192,  16384) us  1",
  "ledger OK  records 40 (this boot 20)  head seq 40 abcd...",
];

test("parses kervixd stats", () => {
  const s = parseStats(STATS);
  assert.deepEqual([s.proposals, s.allow, s.escalate, s.block], [12, 7, 2, 3]);
  assert.equal(s.p50us, 2048);
  assert.equal(s.p99us, 16384);
  assert.equal(s.minUs, 812.4);
  assert.equal(s.uptimeS, 42);
  assert.equal(s.policy, "kervix-default v1.0.0");
  assert.equal(s.hist.length, 4);
  assert.match(String(s.ledger), /^ledger OK/);
  // the empty [2048, 4096) bucket is shown, not skipped
  assert.deepEqual(denseHistogram(s.hist).map((b) => [b.hi, b.n]), [[1024, 3], [2048, 5], [4096, 0], [8192, 3], [16384, 1]]);
  assert.deepEqual(denseHistogram([{ lo: 0, hi: 1, n: 2 }, { lo: 2, hi: 4, n: 1 }]).map((b) => b.lo), [0, 1, 2]);
});

test("reduces bridge messages", () => {
  let st = initialState();
  st = reduce(st, { type: "snapshot", target: "127.0.0.1", gateways: { agent: { up: true, hello: { role: "agent", type: "agentgw_t", uid: 400, prio: 10, pid: 1 } } }, authority: { up: true, since: 1 }, telemetry: { kind: "telemetry", telemetry: { speed_dkph: 0 }, age_us: 900 }, stats: STATS, escalations: [], feed: [] });
  assert.equal(st.connected, true);
  assert.equal(st.gateways.agent.hello?.type, "agentgw_t");
  assert.equal(st.stats?.proposals, 12);
  assert.equal(st.fake, false);
  st = reduce(st, { type: "authority", up: false, since: 2 });
  assert.equal(st.authority.up, false);
  st = reduce(st, { type: "gateway", role: "world", up: true, hello: { role: "world", fake: true } });
  assert.equal(st.fake, true);
  st = reduce(st, { type: "feed", event: { seq: 1, t: 10, source: "agent", msg: { kind: "decision", verdict: "BLOCK", reason: "R156_NOT_SAFE_STATE", intent: { action: "ota.ecu.flash" } } } });
  st = reduce(st, { type: "feed", event: { seq: 2, t: 11, source: "agent", msg: { kind: "note", role: "assistant", text: "hi" } } });
  assert.deepEqual(lastDecision(st.feed), { verdict: "BLOCK", action: "ota.ecu.flash", reason: "R156_NOT_SAFE_STATE", t: 10 });
  for (let i = 0; i < 250; i++) st = reduce(st, { type: "feed", event: { seq: 3 + i, t: 12, source: "x", msg: { kind: "note" } } });
  assert.equal(st.feed.length, 200);
  st = reduce(st, { type: "disconnected" });
  assert.equal(st.connected, false);
});
