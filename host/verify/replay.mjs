// Deterministic replay: re-run the C policy core (libkxcore compiled to
// WebAssembly, the same source that runs in kervixd on QNX) on the inputs
// recorded in a decision capsule, and compare with what was recorded.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const catalog = JSON.parse(readFileSync(join(here, "../shared/catalog.gen.json"), "utf8"));

export async function loadReplay(wasmPath = join(here, "kxcore.wasm"), bodies = new Map()) {
  const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
  const x = instance.exports;
  if (x.kxw_init() !== 0) throw new Error("replay engine: built-in policy failed to build");
  const mem = () => new Uint8Array(x.memory.buffer);
  const hex = (ptr, n) => Buffer.from(mem().subarray(ptr, ptr + n)).toString("hex");
  const cstr = (ptr) => { const m = mem(); let e = ptr; while (m[e]) e++; return Buffer.from(m.subarray(ptr, e)).toString("utf8"); };
  const setStr = (s) => { const b = Buffer.from(s + "\0", "utf8"); mem().set(b, x.kxw_str()); };
  const policyHash = "sha256:" + hex(x.kxw_policy_hash(), 32);   // the built-in policy
  // signed policies shipped in the dossier: body bytes keyed by the hash the C core computes
  let loaded = policyHash;
  const select = (h) => {
    if (h === loaded) return true;
    if (h === policyHash) { x.kxw_init(); loaded = policyHash; return true; }
    const body = bodies.get(h);
    if (!body) return false;
    mem().set(body, x.kxw_body());
    if (x.kxw_load(body.length) !== 0) { loaded = policyHash; return false; }
    loaded = h;
    return true;
  };
  const actions = new Map(catalog.actions.map((a) => [a.name, a]));
  const fields = catalog.telemetry.map((f) => f.name);
  const verdicts = ["NONE", "ALLOW", "ESCALATE", "BLOCK"];
  const gates = ["none", "k4_validation", "expiry", "k1_stale", "k2_implausible", "k3_ledger", "require", "rate_limit"];
  const reasonName = new Map(catalog.reasons.map((r) => [r.id, r.name]));

  /** Replay one decision capsule. Returns { status: "match"|"mismatch"|"skipped", detail } */
  function replay(capsule) {
    const k = capsule.evidence?.kervix;
    if (!k || k.event !== "decision") return { status: "skipped", detail: "not a decision" };
    if (!select(k.policy_hash)) return { status: "unknown_policy", detail: `policy ${k.policy_hash.slice(0, 15)}… is not in the dossier` };
    const it = k.intent, a = actions.get(it.action);
    x.kxw_intent_reset(a ? a.id : 0, BigInt(it.expires_at_ms));
    for (const [name, v] of Object.entries(it.parameters)) {
      const p = a?.params.find((q) => q.name === name);
      if (!p) return { status: "mismatch", detail: `unknown parameter ${name}` };
      if (p.type === "digest") { const b = Buffer.from(String(v).replace(/^sha256:/, ""), "hex"); b.forEach((byte, i) => x.kxw_intent_digest(i, byte)); continue; }
      const val = p.type === "enum" ? catalog.enums[p.enumName].indexOf(v) : p.type === "bool" ? (v ? 1 : 0) : v;
      x.kxw_intent_param(p.key, BigInt(val));
    }
    Buffer.from(it.intent_id.replace(/-/g, ""), "hex").forEach((byte, i) => x.kxw_intent_id(i, byte));
    setStr(it.actor);
    x.kxw_intent_actor();
    const t = k.telemetry;
    x.kxw_tel_reset(BigInt(t.seq), BigInt(t.mono_ns));
    fields.forEach((f, i) => x.kxw_tel_set(i, t[f]));
    x.kxw_env(BigInt(k.env.now_mono_ns), BigInt(k.env.now_rt_ms), BigInt(k.env.max_age_ns), k.env.ledger_ok);
    const r = x.kxw_eval();
    const got = { verdict: verdicts[r & 0xff], gate: gates[(r >> 8) & 0xff], reason: reasonName.get(r >>> 16), rule_id: cstr(x.kxw_rule_id()) };
    const want = { verdict: k.verdict, gate: k.gate, reason: k.reason, rule_id: k.rule_id ?? "" };
    // kervixd may turn the policy's ALLOW/ESCALATE into a BLOCK after kx_eval, never the other way:
    //  - K3 ledger back-pressure (no room to record it: "no audit, no action");
    //  - F12 rate limit (checked against the recorded bucket by the rate pass in verify-lib);
    //  - capacity: grant table full, escalation queue full, no CSPRNG for a grant id.
    // Each is recorded in the evidence and replays as the override that decided.
    const pure = got.verdict;
    const override = want.verdict === "BLOCK" && (pure === "ALLOW" || pure === "ESCALATE");
    if (override && want.gate === "k3_ledger" && want.reason === "LEDGER_PRESSURE") return { status: "match", detail: "ledger back-pressure override (K3)", pure };
    if (override && want.gate === "rate_limit" && want.reason === "RATE_LIMITED") return { status: "match", detail: "rate limit (F12)", pure };
    if (override && want.gate === got.gate && want.rule_id === got.rule_id &&
        ((pure === "ALLOW" && (want.reason === "GRANT_TABLE_FULL" || want.reason === "LEDGER_PRESSURE")) || (pure === "ESCALATE" && want.reason === "ESCALATION_QUEUE_FULL")))
      return { status: "match", detail: `capacity override (${want.reason})`, pure };
    const diffs = Object.keys(want).filter((f) => got[f] !== want[f]);
    if (diffs.length) return { status: "mismatch", detail: diffs.map((f) => `${f}: recorded ${want[f]}, replay ${got[f]}`).join("; "), pure };
    // the intent hash the grant was bound to must be reproducible from the evidence
    if (it.tenant_id && k.intent_hash) {
      setStr(`${it.tenant_id}\n${capsule.operator}\nai_agent`);
      if (x.kxw_intent_hash(BigInt(it.captured_at_ms)) === 0) {
        const h = "sha256:" + hex(x.kxw_hash(), 32);
        if (h !== k.intent_hash) return { status: "mismatch", detail: "intent_hash does not recompute from the recorded intent", pure };
      }
    }
    return { status: "match", detail: "", pure };
  }
  /** Load a policy body with the vehicle's loader; returns its hash or null if rejected. */
  function hashBody(body) {
    if (body.length > x.kxw_body_max()) return null;
    mem().set(body, x.kxw_body());
    const ok = x.kxw_load(body.length) === 0;
    const h = ok ? "sha256:" + hex(x.kxw_policy_hash(), 32) : null;
    x.kxw_init();
    loaded = policyHash;
    return h;
  }
  /** F12: the catalog's rate limit for an action, or null. */
  const rateOf = (name) => actions.get(name)?.rate ?? null;
  /** F12: one step of the vehicle's GCRA (kx_rl_step). tat, now: BigInt ns. */
  function rateStep(burst, perMin, tat, now) {
    const r = x.kxw_rl_step(burst, perMin, tat, now);
    return { conforms: r === 1, valid: r >= 0, after: r === 1 ? BigInt.asUintN(64, x.kxw_rl_after()) : tat };
  }
  return { replay, policyHash, hashBody, rateOf, rateStep, catalogSha: cstr(x.kxw_catalog_sha()) };
}
