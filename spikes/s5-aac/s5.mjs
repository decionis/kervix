// Spike S5. Questions this answers:
//  1. Can we reproduce the pinned draft-04 Producer Envelope vector byte-for-byte
//     with a fixed CBOR template (the approach planned for the C target)?
//  2. Does an independent minimal JCS match @decionis/verify's jcsCanonicalize
//     on Kervix-shaped capsules (integers, ASCII, nested objects/arrays)?
//  3. Does a realistic Kervix capsule stream (epoch, ALLOW+confirm, BLOCK,
//     ESCALATE, human approval, grant replay) pass Class 1 + envelope checks?
//     Which findings are only `info` (unregistered values that U1 will fix)?
import { createHash, createPrivateKey, createPublicKey, sign, generateKeyPairSync } from "node:crypto";
import {
  jcsCanonicalize,
  computeAgentActionCapsuleV04Id,
  verifyAgentActionCapsuleV04Class1,
  verifyAgentActionCapsuleProducerEnvelope,
  intentHash,
} from "@decionis/verify";

const sha256hex = (s) => createHash("sha256").update(s).digest("hex");
let failures = 0;
const check = (ok, label, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? "  — " + detail : ""}`);
  if (!ok) failures++;
};

// ---------------------------------------------------------------- minimal JCS
// The subset Kervix emits: objects, arrays, strings, safe integers, booleans,
// null. This mirrors the bounded serializer planned for libkxcore (C).
function jcs(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("non-integer number");
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const keys = Object.keys(v).sort(); // UTF-16 code-unit order; our keys are ASCII
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
}

// ------------------------------------------------- COSE_Sign1 byte template
// d2 84 | 58 4c <protected: a3 01 27 03 78 23 "application/agent-action-capsule-id" 04 58 20 <pk32>>
//       | a0 | 58 20 <capsule_id32> | 58 40 <sig64>
const CT = Buffer.from("application/agent-action-capsule-id", "ascii"); // 35 bytes = 0x23
function protectedHeader(pk32) {
  return Buffer.concat([Buffer.from([0xa3, 0x01, 0x27, 0x03, 0x78, CT.length]), CT, Buffer.from([0x04, 0x58, 0x20]), pk32]);
}
function sigStructure(prot, payload) {
  // ["Signature1", bstr protected, bstr external_aad(empty), bstr payload]
  return Buffer.concat([
    Buffer.from([0x84, 0x6a]), Buffer.from("Signature1", "ascii"),
    Buffer.from([0x58, prot.length]), prot,
    Buffer.from([0x40]),
    Buffer.from([0x58, 0x20]), payload,
  ]);
}
function coseSign1(privKey, pk32, capsuleIdHex) {
  const prot = protectedHeader(pk32);
  const payload = Buffer.from(capsuleIdHex, "hex");
  const sig = sign(null, sigStructure(prot, payload), privKey);
  return Buffer.concat([
    Buffer.from([0xd2, 0x84, 0x58, prot.length]), prot,
    Buffer.from([0xa0]),
    Buffer.from([0x58, 0x20]), payload,
    Buffer.from([0x58, 0x40]), sig,
  ]);
}
const keyFromSeed = (seedHex) =>
  createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
const rawPub = (priv) => createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32);

// ------------------------------------------------------- Q1: pinned vector
{
  const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"; // RFC 8032 test 1
  const capsuleId = "eea9ad9434749a6771a88fefed0a116fec88e05dbf88f3f807dd547b17efe914";
  const expected = "d284584ca301270378236170706c69636174696f6e2f6167656e742d616374696f6e2d63617073756c652d6964045820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511aa05820eea9ad9434749a6771a88fefed0a116fec88e05dbf88f3f807dd547b17efe91458400c9ff70e4cab6d02cee0be0a6fc49ce7bfd63333d7474d943a497d9bfc0f0b8150a328ba57bee10a0ce19ddf28e31a199038ff2886042392e22c5d063474e30d";
  const k = keyFromSeed(seed);
  const got = coseSign1(k, rawPub(k), capsuleId).toString("hex");
  check(got === expected, "Q1 COSE_Sign1 template reproduces the pinned draft-04 vector byte-for-byte");
}

// ------------------------------------------------------ Q3: capsule stream
const VEHICLE = "veh-3f9a2c71"; // pseudonymous vehicle id (operator)
const DEVELOPER = "kervix:authority:0.1.0";
const EPOCH = "sha256:" + sha256hex("epoch-1");
const POLICY_HASH = "sha256:" + sha256hex("policy kervix-default 1.3.0");
const { privateKey: vehKey } = generateKeyPairSync("ed25519");
const vehPub = rawPub(vehKey);

let t = Date.parse("2026-11-20T10:00:00.000Z");
const ts = () => new Date((t += 37)).toISOString();
const telemetry = (o) => ({ seq: 1000 + (t % 997), speed_dkph: 0, gear: 0, park_brake: 1, soc_dpct: 620, charging: 0, driver_present: 1, ...o });

const intent = (actionName, params, n) => ({
  protocol_version: "agent-safe.intent/1",
  tenant_id: "6f1c2b9e-4d3a-4c8b-9a7e-2b1d0c3e4f5a",
  intent_id: `0b6c1e2a-7f3d-4a9b-8c1d-${String(n).padStart(12, "0")}`,
  captured_at: "2026-11-20T10:00:00.000Z",
  expires_at: "2026-11-20T10:00:05.000Z",
  actor: { id: "agent:cabin-copilot", type: "ai_agent", runtime: "claude-opus-5-5" },
  action: { type: actionName, resource: `vehicle/${VEHICLE}`, parameters: params },
  context: { idempotency_key: `idem-${n}` },
  downstream_target: { system: "sdv_actuatord", operation: actionName, environment: "vehicle" },
});

const stream = [];
let parent = null;
function emit(body, { relation = "follows", parentOverride, references } = {}) {
  const c = {
    spec_version: "draft-mih-scitt-agent-action-capsule-04",
    format_version: "4",
    canonicalization_id: "jcs",
    epoch_id: EPOCH,
    operator: VEHICLE,
    developer: DEVELOPER,
    timestamp: ts(),
    ...body,
  };
  const p = parentOverride ?? parent;
  if (p) c.chain = { parent_capsule_id: p, relation };
  if (references) c.references = references;
  c.assurance = {
    attestation_mode: "self_attested",
    effect_mode: c.effect?.status === "confirmed" ? "confirmed" : ["dispatched", "failed", "reverted"].includes(c.effect?.status) ? "dispatched_unconfirmed" : "not_applicable",
    ledger_mode: p ? "chained" : "standalone",
  };
  // Q2: independent JCS must match the reference implementation
  const preimage = { ...c };
  const mine = jcs(preimage), theirs = jcsCanonicalize(preimage);
  if (mine !== theirs) check(false, "Q2 JCS parity", body.action_id);
  c.capsule_id = sha256hex(mine);
  if (c.capsule_id !== computeAgentActionCapsuleV04Id(c)) check(false, "capsule_id parity", body.action_id);
  stream.push({ capsule: c, envelope: coseSign1(vehKey, vehPub, c.capsule_id) });
  parent = c.capsule_id;
  return c.capsule_id;
}

const rule = (id, result, blocking, evidence) => ({
  id: `com.kervix.policy.${id}`, check_type: "com.kervix.deterministic_policy", method: "com.kervix.kx_eval.v1",
  result, severity: blocking ? "critical" : "info", blocking, evidence_digest: sha256hex(jcs(evidence)),
});
const K = (id, result, evidence) => ({
  id: `com.kervix.constitution.${id}`, check_type: "com.kervix.constitution", method: "com.kervix.kx_eval.v1",
  result, severity: "critical", blocking: true, evidence_digest: sha256hex(jcs(evidence)),
});

// 1) epoch opens (first capsule, standalone)
emit({ action_id: "epoch-1", action_type: "fyi",
  disposition: { decision: "accept", approver: "policy", human_disposed: false, verdict_class: "epoch_boundary", authority: POLICY_HASH },
  evidence: { kervix: { event: "epoch_open", reason: "AUTHORITY_EPOCH", ledger_seq: 1, prior_head: null } } });

// 2) ALLOW climate at 60 km/h, effect planned (no verdict_class: authorized, not yet executed)
const tel1 = telemetry({ speed_dkph: 600, gear: 3, park_brake: 0 });
const in1 = intent("cabin.climate.set", { temp_dc: 225 }, 1);
const ih1 = intentHash(in1).intent_hash;
const d1 = emit({ action_id: in1.intent_id, decision_id: "kx-dec-2", action_type: "decide",
  disposition: { decision: "accept", approver: "policy", human_disposed: false, authority: POLICY_HASH, reason_digest: sha256hex("OK") },
  effect: { type: "vehicle.cabin.climate.set", status: "planned", irreversibility_class: "two_way" },
  constraints: [K("telemetry_fresh", "pass", tel1), rule("climate-any", "pass", false, { in1: ih1, tel1 })],
  evidence: { kervix: { verdict: "ALLOW", reason: "OK", rule_id: "climate-any", intent_hash: ih1, policy_hash: POLICY_HASH, telemetry: tel1, grant_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90", eval_ns: 3120, ledger_seq: 2 } } });

// 3) confirmed effect, directly after its decision -> relation "confirms"
emit({ action_id: in1.intent_id, decision_id: "kx-dec-2", action_type: "decide",
  disposition: { decision: "accept", approver: "policy", human_disposed: false, verdict_class: "executed", authority: POLICY_HASH },
  effect: { type: "vehicle.cabin.climate.set", status: "confirmed", irreversibility_class: "two_way",
    request_digest: sha256hex("cmd cabin.climate.set temp_dc=225"), response_digest: sha256hex("ack hvac_setpoint_dc=225"), effect_attestation: "gate_executed" },
  evidence: { kervix: { grant_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90", redeem_ns: 2410, ledger_seq: 3 } } }, { relation: "confirms", parentOverride: d1 });

// 4) BLOCK ota at 110 km/h (prompt-injection scenario)
const tel2 = telemetry({ speed_dkph: 1100, gear: 3, park_brake: 0 });
const in2 = intent("ota.ecu.flash", { ecu: "brake", image_digest: "sha256:" + sha256hex("fw") }, 2);
emit({ action_id: in2.intent_id, decision_id: "kx-dec-4", action_type: "decide",
  disposition: { decision: "reject", approver: "policy", human_disposed: false, verdict_class: "blocked", authority: POLICY_HASH, reason_digest: sha256hex("R156_NOT_SAFE_STATE") },
  constraints: [K("telemetry_fresh", "pass", tel2), rule("ota-block-moving", "fail", true, { tel2 })],
  evidence: { kervix: { verdict: "BLOCK", reason: "R156_NOT_SAFE_STATE", rule_id: "ota-block-moving", intent_hash: intentHash(in2).intent_hash, policy_hash: POLICY_HASH, telemetry: tel2, eval_ns: 2980, ledger_seq: 4 } } });

// 5) ESCALATE ota when parked + charging
const tel3 = telemetry({ charging: 1 });
const in3 = intent("ota.ecu.flash", { ecu: "brake", image_digest: "sha256:" + sha256hex("fw") }, 3);
emit({ action_id: in3.intent_id, decision_id: "kx-dec-5", action_type: "decide",
  disposition: { decision: "needs_input", approver: "policy", human_disposed: false, verdict_class: "escalated", authority: POLICY_HASH },
  constraints: [rule("ota-escalate-parked", "pass", false, { tel3 })],
  evidence: { kervix: { verdict: "ESCALATE", reason: "DRIVER_CONSENT", escalation_id: 7, telemetry: tel3, ledger_seq: 5 } } });

// 6) driver approves
emit({ action_id: in3.intent_id, decision_id: "kx-dec-5", action_type: "decide",
  disposition: { decision: "accept", approver: "human", human_disposed: true, verdict_class: "resolved", authority: POLICY_HASH },
  evidence: { kervix: { reason: "HUMAN_APPROVED", escalation_id: 7, approver_id: "hmi:driver-seat", ledger_seq: 6 } } });

// 7) replayed grant (grant misuse) -> denied
emit({ action_id: in1.intent_id, decision_id: "kx-redeem-7", action_type: "decide",
  disposition: { decision: "reject", approver: "policy", human_disposed: false, verdict_class: "denied", authority: POLICY_HASH, reason_digest: sha256hex("GRANT_SPENT") },
  evidence: { kervix: { reason: "GRANT_SPENT", grant_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90", client_type: "agentgw_t", ledger_seq: 7 } } });

// 8) a confirmation that does NOT directly follow its decision -> follows + references
emit({ action_id: in3.intent_id, decision_id: "kx-dec-5", action_type: "decide",
  disposition: { decision: "accept", approver: "human", human_disposed: true, verdict_class: "executed", authority: POLICY_HASH },
  effect: { type: "vehicle.ota.ecu.flash", status: "confirmed", irreversibility_class: "one_way_consequential",
    request_digest: sha256hex("cmd ota"), response_digest: sha256hex("ack ota"), effect_attestation: "gate_executed" },
  evidence: { kervix: { ledger_seq: 8 } } },
  { references: [{ type: "aac-capsule", digest_alg: "sha-256", digest: stream[4].capsule.capsule_id, citation_purpose: "responds_to" }] });

// ------------------------------------------------------ verify everything
const known = [];
const infoCodes = new Map();
for (const [i, { capsule, envelope }] of stream.entries()) {
  const r = verifyAgentActionCapsuleV04Class1(capsule, { known_capsules: [...known] });
  const errs = r.checks.flatMap((c) => c.findings.filter((f) => f.severity === "error").map((f) => `${c.name}:${f.code}`));
  for (const c of r.checks) for (const f of c.findings) if (f.severity === "info") infoCodes.set(f.message, (infoCodes.get(f.message) ?? 0) + 1);
  const e = verifyAgentActionCapsuleProducerEnvelope(envelope, capsule.capsule_id);
  const label = `#${i + 1} ${capsule.disposition.verdict_class ?? "(authorized)"} ${capsule.effect?.type ?? ""}`.trim();
  check(r.ok, `Q3 Class 1 ${label}`, errs.join(", "));
  check(e.ok && e.authenticated_public_key_base64url === vehPub.toString("base64url"), `Q3 envelope ${label}`);
  known.push(capsule);
}
console.log(`\nJCS parity on ${stream.length} capsules: ${failures === 0 ? "identical" : "see failures"}`);

// tamper test: flip one byte in an evidence field -> identity must fail
{
  const tampered = structuredClone(stream[3].capsule);
  tampered.evidence.kervix.telemetry.speed_dkph = 0; // pretend the car was parked
  const r = verifyAgentActionCapsuleV04Class1(tampered, { known_capsules: stream.slice(0, 3).map((s) => s.capsule) });
  check(!r.ok && r.checks.find((c) => c.name === "identity")?.ok === false, "Q3 tamper: editing evidence breaks capsule identity");
}

console.log("\nInformational (non-error) findings — expected to disappear after U1:");
for (const [msg, n] of infoCodes) console.log(`  ${n}×  ${msg}`);
console.log(`\n${failures === 0 ? "S5 RESULT: PASS" : `S5 RESULT: ${failures} FAILURE(S)`}`);
process.exit(failures ? 1 : 0);
