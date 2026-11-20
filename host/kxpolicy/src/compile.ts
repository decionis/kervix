// kxpolicy compile: policy YAML -> canonical policy body (format: target/include/kervix/policy.h).
// The body keeps rules in source order and is NOT finalized: the vehicle's C core
// (kx_policy_load) validates, finalizes and hashes it, so defaults and ordering
// are decided in exactly one place. This compiler checks everything it can name
// against the catalog first, so an author sees "unknown field speed_kph at rule
// x" here rather than a bare "rejected" on the vehicle.
import { parse } from "yaml";

import catalog from "../../shared/catalog.gen.json" with { type: "json" };

export class PolicyError extends Error {}

type Cat = typeof catalog;
const SRC = { telemetry: 1, param: 2 } as const;
const FN = { value: 0, absdiff: 1 } as const;
const OPS: Record<string, number> = { "==": 0, "!=": 1, "<": 2, "<=": 3, ">": 4, ">=": 5 };
const VERDICTS: Record<string, number> = { ALLOW: 1, ESCALATE: 2, BLOCK: 3 };
const MAX_RULE_PREDS = 8;
const RULE_ID_LEN = 32;
const POLICY_ID_LEN = 32;
const MAGIC = "kervix.policy-body/1";

type Operand = { src: number; id: number };
type Pred = { a: Operand; b: Operand; fn: number; op: number; group: number; k: bigint };
type Span = { off: number; n: number };
type Rule = { id: string; action: number; verdict: number; reason: number; requireReason: number; when: Span; interlock: Span; require: Span; ttl: number; escTimeout: number };
export type CompiledPolicy = { id: string; version: number; versionText: string; body: Uint8Array; rules: number; preds: number };

const reasonId = (name: string, where: string): number => {
  const r = (catalog as Cat).reasons.find((x) => x.name === name);
  if (!r) throw new PolicyError(`${where}: unknown reason ${name}`);
  return r.id;
};

function operand(text: string, action: Cat["actions"][number], where: string): { op: Operand; enumName: string | null } {
  const t = text.trim();
  if (t.startsWith("param.")) {
    const name = t.slice(6);
    const p = action.params.find((x) => x.name === name);
    if (!p) throw new PolicyError(`${where}: ${action.name} has no parameter ${name}`);
    if (p.type === "digest") throw new PolicyError(`${where}: digest parameter ${name} cannot be compared`);
    return { op: { src: SRC.param, id: p.key }, enumName: p.enumName };
  }
  const f = (catalog as Cat).telemetry.findIndex((x) => x.name === t);
  if (f < 0) throw new PolicyError(`${where}: unknown telemetry field ${t}`);
  return { op: { src: SRC.telemetry, id: f }, enumName: (catalog as Cat).telemetry[f].enum };
}

const NONE: Operand = { src: 0, id: 0 };
const PRED_RE = /^\s*(absdiff\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)|[A-Za-z_.][A-Za-z0-9_.]*)\s*(==|!=|<=|>=|<|>)\s*(-?\d+|[A-Za-z_][A-Za-z0-9_]*)\s*$/;

function pred(text: unknown, action: Cat["actions"][number], group: number, where: string): Pred {
  if (typeof text !== "string") throw new PolicyError(`${where}: a predicate must be "field op value", got ${JSON.stringify(text)}`);
  const m = PRED_RE.exec(text);
  if (!m) throw new PolicyError(`${where}: cannot parse predicate "${text}"`);
  let a: Operand, b: Operand = NONE, fn: number = FN.value, enumName: string | null;
  if (m[2] !== undefined) {
    const x = operand(m[2], action, where), y = operand(m[3], action, where);
    a = x.op; b = y.op; fn = FN.absdiff; enumName = null;
  } else {
    const x = operand(m[1], action, where);
    a = x.op; enumName = x.enumName;
  }
  let k: bigint;
  if (/^-?\d+$/.test(m[5])) k = BigInt(m[5]);
  else {
    const values = enumName ? (catalog as Cat).enums[enumName as keyof Cat["enums"]] as string[] | undefined : undefined;
    const idx = values ? values.indexOf(m[5]) : -1;
    if (idx < 0) throw new PolicyError(`${where}: "${m[5]}" is not a value of ${m[1]}`);
    k = BigInt(idx);
  }
  return { a, b, fn, op: OPS[m[4]], group, k };
}

/** A section (when / interlock / require): a list of predicates and `{ any: [...] }` OR-groups. */
function section(list: unknown, action: Cat["actions"][number], preds: Pred[], where: string): Span {
  const off = preds.length;
  if (list === undefined || list === null) return { off, n: 0 };
  if (!Array.isArray(list)) throw new PolicyError(`${where}: must be a list`);
  let group = 0;
  for (const item of list) {
    if (item && typeof item === "object" && !Array.isArray(item)) {
      const anyList = (item as { any?: unknown }).any;
      if (!Array.isArray(anyList) || Object.keys(item).length !== 1) throw new PolicyError(`${where}: only { any: [...] } groups are allowed`);
      group++;
      for (const p of anyList) preds.push(pred(p, action, group, where));
    } else {
      preds.push(pred(item, action, 0, where));
    }
  }
  const n = preds.length - off;
  if (n > MAX_RULE_PREDS) throw new PolicyError(`${where}: at most ${MAX_RULE_PREDS} predicates`);
  return { off, n };
}

const ALLOWED_RULE_KEYS = new Set(["id", "action", "when", "verdict", "reason", "escalate", "interlock", "grant_ttl_ms"]);

export function compile(yamlText: string): CompiledPolicy {
  const doc = parse(yamlText) as Record<string, unknown>;
  if (!doc || typeof doc !== "object") throw new PolicyError("policy: not a YAML mapping");
  const id = String(doc.policy ?? "");
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(id) || id.length >= POLICY_ID_LEN) throw new PolicyError(`policy id "${id}" must be [a-z0-9._-], < ${POLICY_ID_LEN} chars`);
  const vm = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(doc.version ?? ""));
  if (!vm || vm.slice(1).some((x) => Number(x) > 255)) throw new PolicyError(`version "${doc.version}" must be semver with parts <= 255`);
  const version = (Number(vm[1]) << 16) | (Number(vm[2]) << 8) | Number(vm[3]);
  const def = (doc.default ?? { verdict: "BLOCK", reason: "DEFAULT_DENY" }) as { verdict?: string; reason?: string };
  const defVerdict = VERDICTS[String(def.verdict)];
  if (!defVerdict) throw new PolicyError(`default verdict ${def.verdict}`);
  const defReason = reasonId(String(def.reason ?? "DEFAULT_DENY"), "default");
  if (!Array.isArray(doc.rules)) throw new PolicyError("rules: must be a list");

  const preds: Pred[] = [];
  const rules: Rule[] = [];
  const ids = new Set<string>();
  for (const [i, raw] of (doc.rules as Record<string, unknown>[]).entries()) {
    const where = `rule ${i + 1}${raw?.id ? ` (${raw.id})` : ""}`;
    if (!raw || typeof raw !== "object") throw new PolicyError(`${where}: not a mapping`);
    for (const k of Object.keys(raw)) if (!ALLOWED_RULE_KEYS.has(k)) throw new PolicyError(`${where}: unknown key ${k}`);
    const rid = String(raw.id ?? "");
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(rid) || rid.length >= RULE_ID_LEN) throw new PolicyError(`${where}: id must be [a-z0-9._-], < ${RULE_ID_LEN} chars`);
    if (ids.has(rid)) throw new PolicyError(`${where}: duplicate id`);
    ids.add(rid);
    const action = (catalog as Cat).actions.find((a) => a.name === raw.action);
    if (!action) throw new PolicyError(`${where}: unknown action ${raw.action}`);
    const verdict = VERDICTS[String(raw.verdict)];
    if (!verdict) throw new PolicyError(`${where}: verdict must be ALLOW, ESCALATE or BLOCK`);
    const esc = (raw.escalate ?? {}) as { timeout_ms?: number; require?: unknown; require_reason?: string };
    if (raw.escalate && verdict !== VERDICTS.ESCALATE) throw new PolicyError(`${where}: escalate: only on ESCALATE rules`);
    if (raw.interlock && verdict === VERDICTS.BLOCK) throw new PolicyError(`${where}: interlock: is meaningless on a BLOCK rule`);
    // sections in the order the C core lays out predicates: when, interlock, require
    const when = section(raw.when, action, preds, `${where} when`);
    const interlock = section(raw.interlock, action, preds, `${where} interlock`);
    const require = section(esc.require, action, preds, `${where} escalate.require`);
    const ttl = raw.grant_ttl_ms === undefined ? 0 : Number(raw.grant_ttl_ms);
    const escTimeout = esc.timeout_ms === undefined ? 0 : Number(esc.timeout_ms);
    if (!Number.isInteger(ttl) || ttl < 0 || ttl > 60000) throw new PolicyError(`${where}: grant_ttl_ms must be 0..60000`);
    if (!Number.isInteger(escTimeout) || escTimeout < 0 || escTimeout > 600000) throw new PolicyError(`${where}: escalate.timeout_ms must be 0..600000`);
    rules.push({
      id: rid, action: action.id, verdict, reason: reasonId(String(raw.reason ?? "OK"), where),
      requireReason: require.n ? reasonId(String(esc.require_reason ?? ""), `${where} escalate.require_reason`) : 0,
      when, interlock, require, ttl, escTimeout,
    });
  }
  return { id, version, versionText: `${vm[1]}.${vm[2]}.${vm[3]}`, body: serialize(id, version, defVerdict, defReason, preds, rules), rules: rules.length, preds: preds.length };
}

function serialize(id: string, version: number, defVerdict: number, defReason: number, preds: Pred[], rules: Rule[]): Uint8Array {
  const out: number[] = [];
  const u8 = (v: number) => out.push(v & 0xff);
  const u16 = (v: number) => { u8(v); u8(v >> 8); };
  const u32 = (v: number) => { u16(v & 0xffff); u16(v >>> 16); };
  const i64 = (v: bigint) => { let x = BigInt.asUintN(64, v); for (let i = 0; i < 8; i++) { u8(Number(x & 0xffn)); x >>= 8n; } };
  const fixed = (s: string, n: number) => { const b = Buffer.from(s, "ascii"); for (let i = 0; i < n; i++) u8(i < b.length ? b[i] : 0); };
  const span = (s: Span) => { u16(s.off); u8(s.n); };
  fixed(MAGIC, MAGIC.length);
  fixed(id, POLICY_ID_LEN);
  u32(version);
  u8(defVerdict);
  u16(defReason);
  u16(preds.length);
  for (const p of preds) { u8(p.a.src); u16(p.a.id); u8(p.b.src); u16(p.b.id); u8(p.fn); u8(p.op); u8(p.group); i64(p.k); }
  u16(rules.length);
  for (const r of rules) {
    fixed(r.id, RULE_ID_LEN);
    u16(r.action); u8(r.verdict); u16(r.reason); u16(r.requireReason);
    span(r.when); span(r.interlock); span(r.require);
    u32(r.ttl); u32(r.escTimeout);
  }
  return Uint8Array.from(out);
}
