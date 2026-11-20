// Agent-Safe Intent v1 parity: every binding libkxcore (C) produces must be
// byte-identical to what the independent reference (@decionis/verify) derives,
// hash to the same value, and satisfy the profile's structure (§3).
//   node intent-parity.mjs [path/to/test_intent | captured.jsonl]
//   (a .jsonl file is output captured elsewhere, e.g. `test_intent --emit` run ON QNX)
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bindingFailure, intentHash } from "@decionis/verify";

const root = resolve(fileURLToPath(import.meta.url), "../../..");
const bin = process.argv[2] ?? resolve(root, "build/host/target/libkxcore/tests/test_intent");
const raw = bin.endsWith(".jsonl") ? readFileSync(bin, "utf8") : execFileSync(bin, ["--emit"], { encoding: "utf8" });
const lines = raw.trim().split("\n");

let failures = 0;
for (const [i, line] of lines.entries()) {
  const { canonical, text, hash } = JSON.parse(line);
  const ref = intentHash(canonical);
  const shape = bindingFailure(canonical);
  const problems = [];
  if (ref.canonical_json !== text) problems.push("canonical bytes differ");
  if (ref.intent_hash !== hash) problems.push(`hash differs (ref ${ref.intent_hash})`);
  if (shape !== null) problems.push(`profile structure fails at ${shape}`);
  const label = `#${i + 1} ${canonical.action.type}`;
  if (problems.length) {
    failures++;
    console.log(`FAIL  ${label}: ${problems.join("; ")}`);
  } else {
    console.log(`PASS  ${label}  ${hash.slice(0, 23)}…`);
  }
}
console.log(failures ? `INTENT PARITY: ${failures} FAILURE(S)` : `INTENT PARITY: PASS (${lines.length} vectors, C == @decionis/verify)`);
process.exit(failures ? 1 : 0);
