// The vehicle's C policy core (libkxcore -> host/verify/kxcore.wasm): loads a
// compiled body exactly as kervixd does and evaluates proposals with it, so
// `kxpolicy test` exercises the code that decides on the vehicle.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import catalog from "../../shared/catalog.gen.json" with { type: "json" };

type Exports = Record<string, (...a: (number | bigint)[]) => number> & { memory: WebAssembly.Memory };
const here = path.dirname(fileURLToPath(import.meta.url));
const VERDICTS = ["NONE", "ALLOW", "ESCALATE", "BLOCK"];
const GATES = ["RULE", "K4_VALIDATION", "EXPIRY", "K1_STALE", "K2_IMPLAUSIBLE", "K3_LEDGER", "REQUIRE"];

export type Decision = { verdict: string; reason: string; rule: string; gate: string };
export type Proposal = { action: string; params?: Record<string, string | number | boolean> };

export class PolicyCore {
  private x!: Exports;
  private mem() { return new Uint8Array(this.x.memory.buffer); }
  private cstr(p: number) { const m = this.mem(); let e = p; while (m[e]) e++; return Buffer.from(m.subarray(p, e)).toString("latin1"); }

  static async create(wasm = path.resolve(here, "../../verify/kxcore.wasm")): Promise<PolicyCore> {
    const c = new PolicyCore();
    const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasm), {});
    c.x = instance.exports as unknown as Exports;
    if (c.x.kxw_init() !== 0) throw new Error("built-in policy failed to build");
    return c;
  }
  /** policy hash of whatever is loaded */
  hash(): string { return "sha256:" + Buffer.from(this.mem().subarray(this.x.kxw_policy_hash(), this.x.kxw_policy_hash() + 32)).toString("hex"); }
  builtin(): string { this.x.kxw_init(); return this.hash(); }
  /** Load a compiled body with the vehicle's loader; null if the vehicle would reject it. */
  load(body: Uint8Array): { hash: string; rules: number } | null {
    if (body.length > this.x.kxw_body_max()) return null;
    this.mem().set(body, this.x.kxw_body());
    if (this.x.kxw_load(body.length) !== 0) return null;
    return { hash: this.hash(), rules: this.x.kxw_rule_count() };
  }
  evaluate(p: Proposal, tel: Record<string, number | string>, env: { ledger_ok?: boolean; age_ms?: number } = {}): Decision {
    const a = catalog.actions.find((q) => q.name === p.action);
    if (!a) throw new Error(`unknown action ${p.action}`);
    this.x.kxw_intent_reset(a.id, 0n);
    for (const [name, v] of Object.entries(p.params ?? {})) {
      const ps = a.params.find((q) => q.name === name);
      if (!ps) throw new Error(`${p.action} has no parameter ${name}`);
      if (ps.type === "digest") { Buffer.from(String(v).replace(/^sha256:/, ""), "hex").forEach((b, i) => this.x.kxw_intent_digest(i, b)); continue; }
      const val = ps.type === "enum" ? (catalog.enums as Record<string, string[]>)[ps.enumName as string].indexOf(String(v)) : typeof v === "boolean" ? (v ? 1 : 0) : Number(v);
      if (ps.type === "enum" && val < 0) throw new Error(`${name}: unknown value ${v}`);
      this.x.kxw_intent_param(ps.key, BigInt(val));
    }
    for (let i = 0; i < 16; i++) this.x.kxw_intent_id(i, i === 6 ? 0x40 : i === 8 ? 0x80 : i + 1);
    const actor = Buffer.from("agent:kxpolicy-test\0");
    this.mem().set(actor, this.x.kxw_str());
    this.x.kxw_intent_actor();
    const now = 10_000_000_000n;
    this.x.kxw_tel_reset(1n, now - BigInt((env.age_ms ?? 1) * 1e6));
    catalog.telemetry.forEach((f, i) => {
      const v = tel[f.name];
      const n = typeof v === "string" ? (f.enum ? (catalog.enums as Record<string, string[]>)[f.enum].indexOf(v) : NaN) : (v ?? 0);
      if (Number.isNaN(n) || n < 0 && typeof v === "string") throw new Error(`telemetry ${f.name}: bad value ${v}`);
      this.x.kxw_tel_set(i, n);
    });
    this.x.kxw_env(now, 1_800_000_000_000n, 50_000_000n, env.ledger_ok === false ? 0 : 1);
    const r = this.x.kxw_eval() >>> 0;
    const reason = catalog.reasons.find((q) => q.id === r >>> 16)?.name ?? String(r >>> 16);
    return { verdict: VERDICTS[r & 0xff], gate: GATES[(r >> 8) & 0xff], reason, rule: this.cstr(this.x.kxw_rule_id()) };
  }
}
