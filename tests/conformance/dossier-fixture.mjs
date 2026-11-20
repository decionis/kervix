// CI check on REAL target output: a dossier signed by kervixd on QNX 8.0 must
// verify with kervix-verify, and a one-byte tampered copy must not.
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(import.meta.url), "../../..");
const fixture = join(root, "tests/fixtures/dossier-qnx-qemu-2026-11-20");
const verify = join(root, "host/verify/kervix-verify.mjs");
const run = (dir) => {
  try { return { code: 0, out: execFileSync(process.execPath, [verify, dir], { encoding: "utf8" }) }; }
  catch (e) { return { code: e.status, out: e.stdout }; }
};
let failures = 0;
const ok = run(fixture);
console.log(ok.code === 0 ? "PASS  QNX-signed dossier verifies" : `FAIL  QNX-signed dossier: exit ${ok.code}\n${ok.out}`);
if (ok.code !== 0) failures++;

const t = mkdtempSync(join(tmpdir(), "kx-tamper-"));
cpSync(fixture, t, { recursive: true });
const p = join(t, "capsules.jsonl");
const b = Buffer.from(readFileSync(p));
const at = b.indexOf("\"reason\":\"") + 10;        // flip one character inside the first reason
b[at] = b[at] === 0x41 ? 0x42 : 0x41;
writeFileSync(p, b);
const bad = run(t);
console.log(bad.code === 1 ? "PASS  one-byte tampered copy is rejected" : `FAIL  tampered copy: exit ${bad.code}`);
if (bad.code !== 1) failures++;
console.log(failures ? "DOSSIER FIXTURE: FAIL" : "DOSSIER FIXTURE: PASS");
process.exit(failures ? 1 : 0);
