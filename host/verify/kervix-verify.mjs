#!/usr/bin/env node
// kervix-verify: verify a Kervix dossier offline. No account, no network.
//
//   kervix-verify <dossier-dir> [--json]
//
// A dossier is what `kxctl dossier export` writes: capsules.jsonl, envelopes.txt,
// vehicle.jwk.json, manifest.json. Checks, in order:
//   1 manifest    file hashes, record count, head capsule, sequence range
//   2 key         one Ed25519 OKP key; kid = RFC 7638 thumbprint
//   3 capsules    canonical bytes (RFC 8785), identity, AAC draft-04 Class 1 (@decionis/verify)
//   4 signatures  every Producer Envelope verifies AND is signed by the pinned vehicle key
//   5 chain       each capsule's parent is the previous one; ledger_seq is contiguous; epochs
//   6 semantics   no effect without prior authority for that grant; no grant executed twice;
//                 every escalation resolution follows its escalation
// Exit: 0 verified, 1 a check failed, 2 usage / IO error.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  computeAgentActionCapsuleV04Id,
  jcsCanonicalize,
  verifyAgentActionCapsuleProducerEnvelope,
  verifyAgentActionCapsuleV04Class1,
} from "@decionis/verify";

const args = process.argv.slice(2);
const asJson = args.includes("--json");
const dir = args.find((a) => !a.startsWith("--"));
if (!dir) {
  console.error("usage: kervix-verify <dossier-dir> [--json]");
  process.exit(2);
}

const sha = (b) => createHash("sha256").update(b).digest("hex");
const findings = [];
const fail = (check, where, message) => findings.push({ check, where, message });
const read = (f) => {
  try { return readFileSync(join(dir, f)); } catch (e) { console.error(`kervix-verify: cannot read ${f}: ${e.message}`); process.exit(2); }
};

// 1 manifest ---------------------------------------------------------------
const manifestRaw = read("manifest.json");
const capsRaw = read("capsules.jsonl");
const envsRaw = read("envelopes.txt");
const jwkRaw = read("vehicle.jwk.json");
let manifest;
try { manifest = JSON.parse(manifestRaw); } catch { console.error("kervix-verify: manifest.json is not JSON"); process.exit(2); }
for (const [f, buf] of [["capsules.jsonl", capsRaw], ["envelopes.txt", envsRaw], ["vehicle.jwk.json", jwkRaw]]) {
  if (manifest.files?.[f] !== `sha256:${sha(buf)}`) fail("manifest", f, "file hash does not match the manifest");
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
  if (k.event === "epoch") epochs++;
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
const escalated = new Set();
for (const [i, c] of known.entries()) {
  const k = c.evidence.kervix, where = `capsule #${i + 1}`;
  if (k.event === "decision" && k.verdict === "ALLOW" && k.grant_id) authorized.set(k.grant_id, k.intent_hash);
  if (k.event === "decision" && k.verdict === "ESCALATE") escalated.add(k.escalation_id);
  if (k.event === "escalation_resolved") {
    if (!escalated.has(k.escalation_id)) fail("semantics", where, `resolution of escalation #${k.escalation_id} without a prior escalation`);
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

// report ------------------------------------------------------------------------
const ok = findings.length === 0;
const summary = {
  verified: ok,
  dossier: dir,
  capsules: known.length,
  seq: [manifest.first_seq, manifest.last_seq],
  epochs,
  events: byEvent,
  vehicle_key: key.kid,
  head: prev?.capsule_id ?? null,
  findings,
  informational: Object.fromEntries(info),
};
if (asJson) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  const line = (label, okp, detail) => console.log(`${okp ? "✔" : "✘"} ${label.padEnd(12)} ${detail}`);
  const bad = (c) => findings.filter((f) => f.check === c);
  console.log(`Kervix dossier ${dir}`);
  line("manifest", !bad("manifest").length, `${known.length} capsule(s), seq ${manifest.first_seq}..${manifest.last_seq}`);
  line("key", !bad("key").length, `Ed25519 kid ${key.kid}`);
  line("capsules", !bad("capsules").length, "canonical, self-identifying, AAC draft-04 Class 1 (@decionis/verify)");
  line("signatures", !bad("signatures").length, "every envelope signed by the pinned vehicle key");
  line("chain", !bad("chain").length, `continuous, ${epochs} epoch(s)`);
  line("semantics", !bad("semantics").length, `no unauthorized or repeated actuation (${executed.size} executed grant(s))`);
  console.log(`  events: ${Object.entries(byEvent).map(([e, n]) => `${e}=${n}`).join("  ")}`);
  for (const f of findings) console.log(`  FAIL [${f.check}] ${f.where}: ${f.message}`);
  for (const [m, n] of info) console.log(`  info ${n}x ${m}`);
  console.log(ok ? "VERIFIED" : `NOT VERIFIED (${findings.length} finding(s))`);
}
process.exit(ok ? 0 : 1);
