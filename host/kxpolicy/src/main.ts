#!/usr/bin/env node
// kxpolicy: compile, sign (author, then a different approver), verify and test Kervix policies.
//   kxpolicy compile <policy.yaml> [-o body.bin]        canonical body + the policy hash the vehicle will compute
//   kxpolicy keygen <name> --role author|approver       <name>.key (PKCS#8 PEM, 0600) + a trust-file line
//   kxpolicy author <policy.yaml> --key a.key -o p.kxp  compile and sign as author
//   kxpolicy approve <p.kxp> --key b.key                 review summary + approver signature (must be another key)
//   kxpolicy verify <p.kxp> --trust trust.txt            the vehicle's acceptance check, on the host
//   kxpolicy test <fixture.yaml...>                       fixtures evaluated by the vehicle's C core (WASM)
import fs from "node:fs";

import { addSignature, bodyDigest, check, decode, encode, generateKey, loadPrivateKey, parseTrust, trustLine, type Role } from "./bundle.ts";
import { compile, PolicyError } from "./compile.ts";
import { PolicyCore } from "./core.ts";
import { runFixture } from "./testrun.ts";

const args = process.argv.slice(2);
const opt = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args.splice(i, 2)[1] : undefined; };
const die = (m: string): never => { console.error(`kxpolicy: ${m}`); process.exit(2); };
const cmd = args.shift();

async function describe(body: Uint8Array, label: string) {
  const core = await PolicyCore.create();
  const loaded = core.load(body);
  if (!loaded) die(`${label}: the vehicle's loader rejects this policy`);
  console.log(`${label}: ${loaded!.rules} rules · body ${body.length} B · body sha256 ${bodyDigest(body).toString("hex").slice(0, 16)}…`);
  console.log(`policy hash (what the vehicle will record): ${loaded!.hash}`);
  if (loaded!.hash === core.builtin()) console.log("identical to the vehicle's built-in default policy");
}

try {
  if (cmd === "compile") {
    const file = args[0] ?? die("compile <policy.yaml>");
    const out = opt("-o");
    const c = compile(fs.readFileSync(file, "utf8"));
    console.log(`${c.id} v${c.versionText}: ${c.rules} rules, ${c.preds} predicates`);
    await describe(c.body, file);
    if (out) { fs.writeFileSync(out, c.body); console.log(`wrote ${out}`); }
  } else if (cmd === "keygen") {
    const name = args[0] ?? die("keygen <name> --role author|approver");
    const role = (opt("--role") ?? die("--role author|approver")) as Role;
    if (role !== "author" && role !== "approver") die("--role author|approver");
    const k = generateKey();
    fs.writeFileSync(`${name}.key`, k.privatePem, { mode: 0o600 });
    console.log(`wrote ${name}.key (keep it secret)\ntrust line for the vehicle:\n  ${trustLine(role, k.pub, name)}`);
  } else if (cmd === "author") {
    const file = args[0] ?? die("author <policy.yaml> --key a.key -o p.kxp");
    const key = opt("--key") ?? die("--key"), out = opt("-o") ?? die("-o");
    const c = compile(fs.readFileSync(file, "utf8"));
    await describe(c.body, file);
    fs.writeFileSync(out, encode(addSignature({ body: Buffer.from(c.body), sigs: [] }, "author", loadPrivateKey(fs.readFileSync(key, "utf8")))));
    console.log(`wrote ${out}: signed by the author; needs an approver (kxpolicy approve)`);
  } else if (cmd === "approve") {
    const file = args[0] ?? die("approve <p.kxp> --key b.key");
    const key = opt("--key") ?? die("--key");
    const b = decode(fs.readFileSync(file));
    await describe(b.body, file);
    fs.writeFileSync(file, encode(addSignature(b, "approver", loadPrivateKey(fs.readFileSync(key, "utf8")))));
    console.log(`approved: ${file} now carries author + approver signatures`);
  } else if (cmd === "verify") {
    const file = args[0] ?? die("verify <p.kxp> --trust trust.txt");
    const trust = parseTrust(fs.readFileSync(opt("--trust") ?? die("--trust"), "utf8"));
    const b = decode(fs.readFileSync(file));
    await describe(b.body, file);
    const r = check(b, trust);
    for (const s of r.signers) console.log(`  signed  ${s}`);
    for (const p of r.problems) console.log(`  REJECT  ${p}`);
    console.log(r.ok ? "ACCEPTED: the vehicle would activate this bundle" : "REJECTED");
    process.exit(r.ok ? 0 : 1);
  } else if (cmd === "test") {
    if (!args.length) die("test <fixture.yaml...>");
    const core = await PolicyCore.create();
    let failed = 0;
    for (const f of args) {
      const r = await runFixture(f, core);
      console.log(`== ${f} (policy ${r.policyHash.slice(0, 23)}…)`);
      for (const l of r.lines) console.log(l);
      if (r.uncovered.length) console.log(`NOTE  rules no fixture reached: ${r.uncovered.join(", ")}`);
      console.log(`${r.passed}/${r.passed + r.failed} PASS`);
      failed += r.failed;
    }
    process.exit(failed ? 1 : 0);
  } else {
    die("usage: kxpolicy compile|keygen|author|approve|verify|test (see src/main.ts)");
  }
} catch (e) {
  if (e instanceof PolicyError) die(e.message);
  throw e;
}
