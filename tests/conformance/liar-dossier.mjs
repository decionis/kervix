// Why replay matters. A compromised authority still holds the vehicle key, so
// it can hash, chain and SIGN a decision that contradicts the policy. Checks
// 1-6 (manifest, key, canonical form, signatures, chain, semantics) then all
// pass; only replay can catch it.
// Builds two complete dossiers from libkxcore's capsule stream, signed with the
// RFC 8032 test key: a truthful one (must verify) and one with a signed lie
// (must fail on replay and nothing else).
import { createHash, createPrivateKey, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(import.meta.url), "../../..");
const bin = join(root, "build/host/target/libkxcore/tests/test_capsule");
const verify = join(root, "host/verify/kervix-verify.mjs");
const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"; // RFC 8032 test 1 public key, base64url
const sha = (b) => createHash("sha256").update(b).digest("hex");

function dossier(lie) {
  const rows = execFileSync(bin, lie ? ["--emit", lie] : ["--emit"], { encoding: "utf8" }).trim().split("\n").map((l) => JSON.parse(l));
  const dir = mkdtempSync(join(tmpdir(), lie ? "kx-liar-" : "kx-honest-"));
  const caps = rows.map((r) => r.text).join("\n") + "\n";
  const envs = rows.map((r) => {
    const env = Buffer.from(r.envelope_unsigned, "hex");
    sign(null, Buffer.from(r.sig_structure, "hex"), key).copy(env, env.length - 64);
    return env.toString("base64url");
  }).join("\n") + "\n";
  const kid = createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest("base64url");
  const jwk = JSON.stringify({ keys: [{ alg: "EdDSA", crv: "Ed25519", kid, kty: "OKP", use: "sig", x }] }) + "\n";
  writeFileSync(join(dir, "capsules.jsonl"), caps);
  writeFileSync(join(dir, "envelopes.txt"), envs);
  writeFileSync(join(dir, "vehicle.jwk.json"), jwk);
  const last = rows.at(-1).capsule;
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({
    files: { "capsules.jsonl": `sha256:${sha(caps)}`, "envelopes.txt": `sha256:${sha(envs)}`, "vehicle.jwk.json": `sha256:${sha(jwk)}` },
    first_seq: 1, format: "kervix.dossier/1", head_capsule_id: last.capsule_id, last_seq: rows.length, records: rows.length,
  }));
  return dir;
}
const run = (dir) => {
  try { return JSON.parse(execFileSync(process.execPath, [verify, dir, "--json"], { encoding: "utf8" })); }
  catch (e) { return JSON.parse(e.stdout); }
};

let failures = 0;
const honest = run(dossier(false));
const okHonest = honest.verified && honest.replay.mismatch === 0 && honest.replay.match > 0;
console.log(`${okHonest ? "PASS" : "FAIL"}  truthful signed dossier verifies; replay ${honest.replay.match}/${honest.replay.match + honest.replay.mismatch}`);
if (!okHonest) { failures++; console.log(JSON.stringify(honest.findings)); }

const liar = run(dossier("--lie"));
const checks = [...new Set(liar.findings.map((f) => f.check))];
const okLiar = !liar.verified && checks.length === 1 && checks[0] === "replay";
console.log(`${okLiar ? "PASS" : "FAIL"}  signed lie (OTA at 110 km/h recorded as ALLOW): checks 1-6 pass, replay rejects it`);
for (const f of liar.findings) console.log(`      ${f.check} ${f.where}: ${f.message}`);
if (!okLiar) failures++;
const hashLie = run(dossier("--lie-hash"));
const hc = [...new Set(hashLie.findings.map((f) => f.check))];
const okHash = !hashLie.verified && hc.length === 1 && hc[0] === "replay" &&
  hashLie.findings.some((f) => f.message.includes("intent_hash does not recompute"));
console.log(`${okHash ? "PASS" : "FAIL"}  signed grant bound to an intent hash that is not the recorded intent's: replay rejects it`);
if (!okHash) { failures++; console.log(JSON.stringify(hashLie.findings)); }
console.log(failures ? "LIAR DOSSIER: FAIL" : "LIAR DOSSIER: PASS");
process.exit(failures ? 1 : 0);
