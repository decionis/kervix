// Capsule parity: every capsule libkxcore (C) builds must be
//  1. canonical: its bytes == jcsCanonicalize(parsed) of the reference implementation
//  2. self-identifying: computeAgentActionCapsuleV04Id(capsule) == capsule_id
//  3. Class 1 valid with the chain resolved against the preceding capsules
//     (only `info` findings allowed: the unregistered `follows` / `vehicle.*` until U1)
//  4. envelope-correct: Node signs the C Sig_structure with the RFC 8032 key, the C
//     envelope template + that signature verifies as a draft-04 Producer Envelope
//   node capsule-parity.mjs [path/to/test_capsule | captured.jsonl]
import { createPrivateKey, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  computeAgentActionCapsuleV04Id,
  jcsCanonicalize,
  verifyAgentActionCapsuleProducerEnvelope,
  verifyAgentActionCapsuleV04Class1,
} from "@decionis/verify";

const root = resolve(fileURLToPath(import.meta.url), "../../..");
const src = process.argv[2] ?? resolve(root, "build/host/target/libkxcore/tests/test_capsule");
const raw = src.endsWith(".jsonl") ? readFileSync(src, "utf8") : execFileSync(src, ["--emit"], { encoding: "utf8" });
const rows = raw.trim().split("\n").map((l) => JSON.parse(l));

const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });

let failures = 0;
const known = [];
const info = new Map();
for (const [i, { capsule, text, sig_structure, envelope_unsigned }] of rows.entries()) {
  const problems = [];
  if (jcsCanonicalize(capsule) !== text) problems.push("not canonical");
  if (computeAgentActionCapsuleV04Id(capsule) !== capsule.capsule_id) problems.push("capsule_id mismatch");
  const r = verifyAgentActionCapsuleV04Class1(capsule, { known_capsules: [...known] });
  for (const c of r.checks) for (const f of c.findings) {
    if (f.severity === "error") problems.push(`${c.name}:${f.code}`);
    else info.set(f.message, (info.get(f.message) ?? 0) + 1);
  }
  const env = Buffer.from(envelope_unsigned, "hex");
  sign(null, Buffer.from(sig_structure, "hex"), key).copy(env, env.length - 64);
  const e = verifyAgentActionCapsuleProducerEnvelope(env, capsule.capsule_id);
  if (!e.ok) problems.push("envelope does not verify");
  const k = capsule.evidence.kervix;
  const label = `#${String(i + 1).padStart(2)} ${(capsule.disposition.verdict_class ?? "(authorized)").padEnd(14)} ${k.event}${k.reason ? " " + k.reason : ""}`;
  console.log(`${problems.length ? "FAIL" : "PASS"}  ${label}${problems.length ? "  — " + problems.join(", ") : ""}`);
  if (problems.length) failures++;
  known.push(capsule);
}
for (const [m, n] of info) console.log(`INFO  ${n}x ${m}`);
console.log(failures ? `CAPSULE PARITY: ${failures} FAILURE(S)` : `CAPSULE PARITY: PASS (${rows.length} capsules, C == @decionis/verify, chain + envelopes verified)`);
process.exit(failures ? 1 : 0);
