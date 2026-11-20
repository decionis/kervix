#!/usr/bin/env node
// kervix-verify: verify a Kervix dossier offline. No account, no network.
//
//   kervix-verify <dossier-dir> [--json]
//
// A dossier is what `kxctl dossier export` writes: capsules.jsonl, envelopes.txt,
// vehicle.jwk.json, manifest.json, and policies/*.kxp (every signed policy that was
// in force). Checks, in order:
//   1 manifest    file hashes, record count, head capsule, sequence range
//   2 key         one Ed25519 OKP key; kid = RFC 7638 thumbprint
//   3 capsules    canonical bytes (RFC 8785), identity, AAC draft-04 Class 1 (@decionis/verify)
//   4 signatures  every Producer Envelope verifies AND is signed by the pinned vehicle key
//   5 chain       each capsule's parent is the previous one; ledger_seq is contiguous; epochs
//   6 semantics   no effect without prior authority for that grant; no grant executed twice;
//                 every escalation resolution follows its escalation, at most once
//   7 replay      every decision is re-evaluated by the SAME C policy core that runs on the
//                 vehicle (libkxcore -> WebAssembly) on the recorded intent, telemetry and
//                 environment: verdict, gate, reason and rule must reproduce, and the intent
//                 hash the grant was bound to must recompute. Signatures prove WHO recorded a
//                 decision; replay proves the decision FOLLOWS from the policy. Each
//                 decision replays under the policy IT records: the built-in one, or a
//                 signed bundle from policies/ (author + approver Ed25519 signatures
//                 checked here). A decision under a policy the dossier lacks fails.
// Exit: 0 verified, 1 a check failed, 2 usage / IO error.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { DossierError, verifyDossier } from "./verify-lib.mjs";

const args = process.argv.slice(2);
const asJson = args.includes("--json");
const dir = args.find((a) => !a.startsWith("--"));
if (!dir) {
  console.error("usage: kervix-verify <dossier-dir> [--json]");
  process.exit(2);
}
const files = new Map();
for (const f of ["manifest.json", "capsules.jsonl", "envelopes.txt", "vehicle.jwk.json"]) {
  try { files.set(f, readFileSync(join(dir, f))); } catch (e) { console.error(`kervix-verify: cannot read ${f}: ${e.message}`); process.exit(2); }
}
if (existsSync(join(dir, "policies"))) for (const f of readdirSync(join(dir, "policies"))) files.set(`policies/${f}`, readFileSync(join(dir, "policies", f)));
let summary;
try {
  summary = await verifyDossier({ files, wasm: args.find((a) => a.startsWith("--wasm="))?.slice(7) });
} catch (e) {
  if (e instanceof DossierError) { console.error(`kervix-verify: ${e.message}`); process.exit(2); }
  throw e;
}
const ui = summary._ui;
summary = { dossier: dir, ...summary };
const { findings, policies, replay, recoveries, epochs, manifest, key, info, byEvent, known } = ui;
const ok = summary.verified;
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
  line("chain", !bad("chain").length, `continuous, ${epochs} epoch(s)` +
       (recoveries.length ? `; restarts: ${recoveries.map((r) => `#${r.restart} after ${r.cause} (seq ${r.seq})`).join(", ")}` : ""));
  line("semantics", !bad("semantics").length, `no unauthorized or repeated actuation (${summary.executed} executed grant(s))`);
  if (policies.length || bad("policy").length)
    line("policies", !bad("policy").length, `${policies.length} signed bundle(s): ` +
         policies.map((p) => `${p.hash.slice(7, 19)}… author ${p.author}… approver ${p.approver}…`).join("; "));
  line("replay", !bad("replay").length, `${replay.match}/${replay.match + replay.mismatch + replay.unknown_policy} decision(s) reproduced by the vehicle's own policy core (WASM)` +
       (replay.policies.size > 1 ? ` under ${replay.policies.size} policies` : "") +
       (replay.k3 ? `, ${replay.k3} ledger back-pressure override(s)` : ""));
  console.log(`  events: ${Object.entries(byEvent).map(([e, n]) => `${e}=${n}`).join("  ")}`);
  for (const f of findings) console.log(`  FAIL [${f.check}] ${f.where}: ${f.message}`);
  for (const [m, n] of info) console.log(`  info ${n}x ${m}`);
  console.log(ok ? "VERIFIED" : `NOT VERIFIED (${findings.length} finding(s))`);
}
process.exit(ok ? 0 : 1);
