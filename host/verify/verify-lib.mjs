// kervix-verify as a library: the checks of the CLI (kervix-verify.mjs), on an
// in-memory dossier, so the bridge's Verify button runs exactly the same code.
//   const summary = await verifyDossier({ files: Map<name, Buffer> })
// files: manifest.json, capsules.jsonl, envelopes.txt, vehicle.jwk.json and
// every policies/<hash16>.kxp the manifest lists. Throws DossierError when the
// dossier is unreadable (missing file, manifest not JSON).
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { loadReplay } from "./replay.mjs";
import {
  computeAgentActionCapsuleV04Id,
  jcsCanonicalize,
  verifyAgentActionCapsuleProducerEnvelope,
  verifyAgentActionCapsuleV04Class1,
} from "@decionis/verify";

export class DossierError extends Error {}

export async function verifyDossier({ files, wasm } = {}) {
  const sha = (b) => createHash("sha256").update(b).digest("hex");
  const findings = [];
  const fail = (check, where, message) => findings.push({ check, where, message });
  const read = (f) => {
    const b = files.get(f);
    if (!b) throw new DossierError(`missing file ${f}`);
    return b;
  };

  // 1 manifest ---------------------------------------------------------------
  const manifestRaw = read("manifest.json");
  const capsRaw = read("capsules.jsonl");
  const envsRaw = read("envelopes.txt");
  const jwkRaw = read("vehicle.jwk.json");
  let manifest;
  try { manifest = JSON.parse(manifestRaw); } catch { throw new DossierError("manifest.json is not JSON"); }
  for (const [f, buf] of [["capsules.jsonl", capsRaw], ["envelopes.txt", envsRaw], ["vehicle.jwk.json", jwkRaw]]) {
    if (manifest.files?.[f] !== `sha256:${sha(buf)}`) fail("manifest", f, "file hash does not match the manifest");
  }
  // signed policies (policies/*.kxp): structure, both signatures, then the C core computes the hash
  const policyFiles = Object.keys(manifest.files ?? {}).filter((f) => /^policies\/[0-9a-f]{16}\.kxp$/.test(f));
  const bundles = [];
  for (const f of policyFiles) {
    const buf = read(f);
    if (manifest.files[f] !== `sha256:${sha(buf)}`) fail("manifest", f, "file hash does not match the manifest");
    const b = decodeBundle(buf);
    if (!b) { fail("policy", f, "not a well-formed .kxp bundle"); continue; }
    const roles = {};
    for (const sgn of b.sigs) {
      const msg = Buffer.concat([Buffer.from("kervix.policy-signature/1\0"), Buffer.from([sgn.role]), createHash("sha256").update(b.body).digest()]);
      const keyObj = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), sgn.pub]), format: "der", type: "spki" });
      if (!edVerify(null, msg, keyObj, sgn.sig)) fail("policy", f, `${sgn.role === 1 ? "author" : "approver"} signature does not verify`);
      roles[sgn.role] = sgn.pub.toString("hex");
    }
    if (!roles[1] || !roles[2]) fail("policy", f, "needs an author and an approver signature");
    else if (roles[1] === roles[2]) fail("policy", f, "author and approver are the same key");
    bundles.push({ file: f, body: b.body, author: roles[1], approver: roles[2] });
  }
  function decodeBundle(buf) {
    if (buf.length < 9 || buf.subarray(0, 4).toString() !== "KXP1") return null;
    const n = buf.readUInt32LE(4);
    if (n > buf.length - 9) return null;
    const count = buf[8 + n];
    if (count > 2 || buf.length !== 9 + n + count * 97) return null;
    const sigs = [];
    for (let i = 0; i < count; i++) { const o = 9 + n + i * 97; sigs.push({ role: buf[o], pub: buf.subarray(o + 1, o + 33), sig: buf.subarray(o + 33, o + 97) }); }
    return { body: buf.subarray(8, 8 + n), sigs };
  }
  const lines = capsRaw.toString("utf8").split("\n").filter((l) => l.length);
  const envs = envsRaw.toString("utf8").split("\n").filter((l) => l.length);
  if (lines.length !== manifest.records || envs.length !== manifest.records) fail("manifest", "records", `manifest says ${manifest.records}, found ${lines.length} capsules / ${envs.length} envelopes`);

  // 2 key ---------------------------------------------------------------------
  let key;
  try { key = JSON.parse(jwkRaw).keys; } catch { key = null; }
  if (!Array.isArray(key) || key.length !== 1 || key[0].kty !== "OKP" || key[0].crv !== "Ed25519" || typeof key[0].x !== "string") {
    fail("key", "vehicle.jwk.json", "expected exactly one OKP/Ed25519 key");
    key = [{ x: "" }];
  }
  key = key[0];
  const thumb = createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${key.x}"}`).digest("base64url");
  if (key.kid !== thumb) fail("key", "kid", "kid is not the RFC 7638 thumbprint of the key");

  // 3-5 capsules, signatures, chain -------------------------------------------
  const known = [];
  const info = new Map();
  const byEvent = {};
  let epochs = 0, prev = null;
  const recoveries = []; // epochs opened by a supervised restart: { seq, restart, cause }
  for (const [i, line] of lines.entries()) {
    const where = `capsule #${i + 1}`;
    let c;
    try { c = JSON.parse(line); } catch { fail("capsules", where, "not JSON"); continue; }
    if (jcsCanonicalize(c) !== line) fail("capsules", where, "bytes are not canonical (RFC 8785): modified after signing?");
    if (computeAgentActionCapsuleV04Id(c) !== c.capsule_id) fail("capsules", where, "capsule_id does not match its content: TAMPERED");
    const r = verifyAgentActionCapsuleV04Class1(c, { known_capsules: [...known] });
    for (const ch of r.checks) for (const f of ch.findings) {
      if (f.severity === "error") fail("capsules", where, `${ch.name}: ${f.code}`);
      else info.set(f.message, (info.get(f.message) ?? 0) + 1);
    }
    const e = verifyAgentActionCapsuleProducerEnvelope(Buffer.from(envs[i] ?? "", "base64url"), c.capsule_id);
    if (!e.ok) fail("signatures", where, "producer envelope does not verify");
    else if (e.authenticated_public_key_base64url !== key.x) fail("signatures", where, "signed by a key other than the pinned vehicle key");
    const k = c.evidence?.kervix ?? {};
    byEvent[k.event] = (byEvent[k.event] ?? 0) + 1;
    if (k.event === "epoch") {
      epochs++;
      if (k.recovery) {
        const r = k.recovery;
        if (!Number.isInteger(r.restart) || r.restart < 1 || typeof r.cause !== "string" || !/^[A-Za-z0-9_]{1,15}$/.test(r.cause))
          fail("semantics", where, "malformed recovery record on an epoch capsule");
        else recoveries.push({ seq: k.ledger_seq, restart: r.restart, cause: r.cause });
      }
    } else if (k.recovery) fail("semantics", where, "recovery record on a non-epoch capsule");
    if (i === 0 && c.chain && c.chain.relation !== "epoch_opens") fail("chain", where, "first capsule chains to something outside the dossier");
    if (i > 0) {
      if (!c.chain || c.chain.parent_capsule_id !== prev.capsule_id) fail("chain", where, "parent is not the previous capsule: inserted, removed or reordered");
      if (k.ledger_seq !== prev.evidence?.kervix?.ledger_seq + 1) fail("chain", where, `ledger_seq ${k.ledger_seq} does not follow ${prev.evidence?.kervix?.ledger_seq}`);
    }
    if (c.chain?.relation === "epoch_opens" && k.event !== "epoch") fail("chain", where, "epoch_opens on a non-epoch capsule");
    known.push(c);
    prev = c;
  }
  if (prev && manifest.head_capsule_id !== prev.capsule_id) fail("manifest", "head", "head capsule id does not match the last capsule");

  // 6 semantics -----------------------------------------------------------------
  const authorized = new Map(); // grant_id -> intent_hash
  const executed = new Set();
  // escalation ids are per epoch: kervixd numbers them from 1 after every (re)start
  const escalated = new Set();
  const resolved = new Set();
  let epoch = 0;
  for (const [i, c] of known.entries()) {
    const k = c.evidence.kervix, where = `capsule #${i + 1}`;
    if (k.event === "epoch") epoch++;
    const esc = `${epoch}:${k.escalation_id}`;
    if (k.event === "decision" && k.verdict === "ALLOW" && k.grant_id) authorized.set(k.grant_id, k.intent_hash);
    if (k.event === "decision" && k.verdict === "ESCALATE") escalated.add(esc);
    if (k.event === "escalation_resolved") {
      if (!escalated.has(esc)) fail("semantics", where, `resolution of escalation #${k.escalation_id} without a prior escalation in this epoch`);
      else if (resolved.has(esc)) fail("semantics", where, `escalation #${k.escalation_id} resolved twice`);
      resolved.add(esc);
      if (k.verdict === "ALLOW" && k.grant_id) authorized.set(k.grant_id, k.intent_hash);
    }
    if (k.event === "effect") {
      if (!authorized.has(k.grant_id)) fail("semantics", where, "actuation without a prior authorization for its grant");
      else if (authorized.get(k.grant_id) !== k.intent_hash) fail("semantics", where, "actuation does not match the authorized intent");
      if (c.effect?.status === "confirmed") {
        if (executed.has(k.grant_id)) fail("semantics", where, "grant executed twice");
        executed.add(k.grant_id);
      }
    }
  }

  // 7 replay ----------------------------------------------------------------------
  const bodies = new Map();
  const engine = await loadReplay(wasm, bodies);
  const policies = [];   // { hash, file, author, approver }
  for (const b of bundles) {
    const h = engine.hashBody(b.body);
    if (!h) { fail("policy", b.file, "the vehicle's policy loader rejects this body"); continue; }
    bodies.set(h, b.body);
    policies.push({ hash: h, file: b.file, author: b.author.slice(0, 16), approver: b.approver.slice(0, 16) });
  }
  for (const [i, c] of known.entries()) {   // every activation must ship its bundle
    const k = c.evidence?.kervix;
    if (k?.event === "policy_activated" && !bodies.has(k.policy_hash)) fail("policy", `capsule #${i + 1}`, `activated policy ${k.policy_hash.slice(0, 15)}… is not in the dossier`);
  }
  const replay = { match: 0, mismatch: 0, unknown_policy: 0, skipped: 0, k3: 0, capacity: 0, policies: new Set() };
  const pureVerdict = new Map();   // capsule index -> what the policy alone decided
  for (const [i, c] of known.entries()) {
    if (c.evidence?.kervix?.event !== "decision") continue;
    const r = engine.replay(c);
    replay[r.status]++;
    if (r.status === "match") { replay.policies.add(c.evidence.kervix.policy_hash); pureVerdict.set(i, r.pure); }
    if (r.detail.includes("K3")) replay.k3++;
    if (r.detail.startsWith("capacity")) replay.capacity++;
    if (r.status === "mismatch") fail("replay", `capsule #${i + 1}`, `decision does not follow from the policy: ${r.detail}`);
    if (r.status === "unknown_policy") fail("replay", `capsule #${i + 1}`, `decided under a policy that cannot be checked: ${r.detail}`);
  }

  // 8 rate limits (F12) -------------------------------------------------------------
  // Each epoch capsule names the principals (secpol types) its limiter covers. Every decision
  // the limiter had to see records the bucket it was made on; the vehicle's own GCRA (WASM)
  // re-decides it, and consecutive decisions on one bucket must chain.
  const rate = { checked: 0, limited: 0, epochs_without: 0, gaps: 0 };
  const rateCfg = new Map();      // epoch_id -> { all, types } | null (epoch predates F12)
  const bucket = new Map();       // epoch|type|action -> tat after the last recorded decision
  for (const [i, c] of known.entries()) {
    const k = c.evidence?.kervix, where = `capsule #${i + 1}`;
    if (k?.event === "epoch") {
      const cfg = k.rate && Number.isInteger(k.rate.all_types) && Array.isArray(k.rate.types) ? { all: k.rate.all_types === 1, types: new Set(k.rate.types) } : null;
      if (!cfg) rate.epochs_without++;
      rateCfg.set(c.epoch_id, cfg);
      continue;
    }
    if (k?.event !== "decision" || !pureVerdict.has(i)) continue;   // replay failures are already findings
    const recorded = !!k.rate || k.gate === "rate_limit";
    if (!rateCfg.has(c.epoch_id)) { if (recorded) info.set("rate-limit decisions from an epoch whose start is not in the dossier (not checked)", (info.get("rate-limit decisions from an epoch whose start is not in the dossier (not checked)") ?? 0) + 1); continue; }
    const cfg = rateCfg.get(c.epoch_id), lim = engine.rateOf(k.intent?.action), pure = pureVerdict.get(i);
    const due = !!cfg && !!lim && (cfg.all || cfg.types.has(k.client_type)) && (pure === "ALLOW" || pure === "ESCALATE") && k.gate !== "k3_ledger";
    if (!due) { if (recorded) fail("rate", where, "records a rate-limit check the limiter could not have made"); continue; }
    if (!k.rate) { fail("rate", where, `the rate limiter was skipped (principal type ${k.client_type}, ${k.intent.action})`); continue; }
    if (k.rate.burst !== lim.burst || k.rate.per_min !== lim.per_min) { fail("rate", where, `limit ${k.rate.burst} + ${k.rate.per_min}/min differs from the catalog's ${lim.burst} + ${lim.per_min}/min`); continue; }
    rate.checked++;
    if (k.rate.overflow === 1) { if (k.gate === "rate_limit") rate.limited++; else fail("rate", where, "no bucket was left for the principal, yet it was not limited"); continue; }
    if (!Number.isSafeInteger(k.rate.tat_ns) || k.rate.tat_ns < 0 || !Number.isSafeInteger(k.env?.now_mono_ns)) { fail("rate", where, "malformed rate evidence"); continue; }
    const key = `${c.epoch_id}|${k.client_type}|${k.intent.action}`, tat = BigInt(k.rate.tat_ns), last = bucket.get(key) ?? 0n;
    if (tat < last) fail("rate", where, "bucket state rolled back: a charge from an earlier decision is missing");
    else if (tat > last) rate.gaps++;
    const step = engine.rateStep(lim.burst, lim.per_min, tat, BigInt(k.env.now_mono_ns));
    if (step.conforms && k.gate === "rate_limit") fail("rate", where, "BLOCKed as RATE_LIMITED although within its rate limit");
    if (!step.conforms && k.gate !== "rate_limit")
      fail("rate", where, `exceeded its rate limit (${lim.burst} back to back, then ${lim.per_min}/min) but was ${k.verdict === "BLOCK" ? "blocked for another reason" : `not limited (${k.verdict})`}`);
    if (k.gate === "rate_limit") rate.limited++;
    bucket.set(key, step.after);
  }
  if (rate.gaps) info.set("rate-limit charges with no recorded decision between them (decisions lost while the ledger was unhealthy?)", rate.gaps);

  const ok = findings.length === 0;
  const summary = {
    verified: ok,
    capsules: known.length,
    seq: [manifest.first_seq, manifest.last_seq],
    epochs,
    recoveries,
    events: byEvent,
    vehicle_key: key.kid,
    head: prev?.capsule_id ?? null,
    replay: { ...replay, policies: [...replay.policies] },
    rate,
    executed: executed.size,
    policies,
    findings,
    informational: Object.fromEntries(info),
  };

  // raw values for the CLI's report (not part of the JSON summary)
  Object.defineProperty(summary, "_ui", { enumerable: false, value: { findings, policies, replay, rate, recoveries, epochs, manifest, key, info, byEvent, known } });
  return summary;
}
