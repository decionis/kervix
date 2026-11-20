import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { addSignature, check, decode, encode, generateKey, loadPrivateKey, parseTrust, trustLine, type Bundle } from "../src/bundle.ts";
import { compile, PolicyError } from "../src/compile.ts";
import { PolicyCore } from "../src/core.ts";
import { runFixture } from "../src/testrun.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const yamlText = fs.readFileSync(path.join(root, "policies/default.yaml"), "utf8");
let core: PolicyCore;
before(async () => { core = await PolicyCore.create(); });

test("the YAML policy, compiled here and loaded by the vehicle's C core, IS the built-in policy (same hash)", () => {
  const builtin = core.builtin();
  const c = compile(yamlText);
  const loaded = core.load(c.body);
  assert.ok(loaded);
  assert.equal(loaded.hash, builtin);
  assert.equal(loaded.rules, 22);
  // the committed body fixture (used by the C loader test) is exactly the compiler's output
  assert.deepEqual(Buffer.from(c.body), fs.readFileSync(path.join(root, "tests/fixtures/policy-default.body")));
});

test("any change to the policy changes its hash", () => {
  const changed = compile(yamlText.replace("speed_dkph > 800, param.pos_pct > 50", "speed_dkph > 900, param.pos_pct > 50"));
  const h = core.load(changed.body)?.hash;
  assert.ok(h && h !== core.builtin());
});

test("the vehicle's loader rejects truncated bodies, trailing bytes and a bad magic", () => {
  const body = compile(yamlText).body;
  for (let n = 0; n < body.length; n += 7) assert.equal(core.load(body.subarray(0, n)), null, `prefix ${n}`);
  assert.equal(core.load(Buffer.concat([body, Buffer.from([0])])), null);
  const bad = Buffer.from(body);
  bad[0] ^= 1;
  assert.equal(core.load(bad), null);
  assert.ok(core.load(body));
});

test("fixtures: every rule and constitution gate, on the vehicle's core", async () => {
  const r = await runFixture(path.join(root, "policies/tests/default.yaml"), core);
  assert.equal(r.failed, 0, r.lines.filter((l) => l.startsWith("FAIL")).join("\n"));
  assert.ok(r.passed >= 28);
  assert.deepEqual(r.uncovered, []);
});

test("signing: author then a DIFFERENT approver; the vehicle's acceptance rule", () => {
  const a = generateKey(), p = generateKey(), stranger = generateKey();
  const trust = parseTrust([trustLine("author", a.pub, "policy-team"), trustLine("approver", p.pub, "safety-board")].join("\n"));
  const body = Buffer.from(compile(yamlText).body);
  const authored = addSignature({ body, sigs: [] }, "author", loadPrivateKey(a.privatePem));
  assert.deepEqual(check(authored, trust).problems, ["missing approver signature"]);
  assert.throws(() => addSignature(authored, "approver", loadPrivateKey(a.privatePem)), /different keys/);
  const full = addSignature(authored, "approver", loadPrivateKey(p.privatePem));
  const round = decode(encode(full));
  const ok = check(round, trust);
  assert.equal(ok.ok, true, ok.problems.join("; "));
  assert.deepEqual(ok.signers, ["author: policy-team", "approver: safety-board"]);

  // an approver key that is not trusted for that role
  const rogue = addSignature(authored, "approver", loadPrivateKey(stranger.privatePem));
  assert.match(check(rogue, trust).problems.join(), /not trusted as approver/);
  // roles are not interchangeable: the approver's key cannot author
  const swapped = parseTrust([trustLine("author", p.pub, "x"), trustLine("approver", a.pub, "y")].join("\n"));
  assert.equal(check(round, swapped).ok, false);
  // a one-bit change to the signed body breaks both signatures
  const tampered: Bundle = { body: Buffer.from(round.body), sigs: round.sigs };
  tampered.body[tampered.body.length - 1] ^= 1;
  assert.match(check(tampered, trust).problems.join(), /author signature does not verify.*approver signature does not verify/);
  assert.throws(() => decode(Buffer.concat([encode(full), Buffer.from([1])])), /malformed/);
});

test("the compiler names mistakes against the catalog", () => {
  const rule = (r: string) => `policy: t\nversion: 1.0.0\nrules:\n  - ${r}\n`;
  const err = (r: string) => { try { compile(rule(r)); return ""; } catch (e) { assert.ok(e instanceof PolicyError); return (e as Error).message; } };
  assert.match(err("{ id: a, action: cabin.climate.set, when: [ speed_kph > 1 ], verdict: ALLOW }"), /unknown telemetry field speed_kph/);
  assert.match(err("{ id: a, action: body.door.unlock, when: [ gear == X ], verdict: ALLOW }"), /"X" is not a value of gear/);
  assert.match(err("{ id: a, action: body.door.unlock, when: [ param.window == 1 ], verdict: ALLOW }"), /no parameter window/);
  assert.match(err("{ id: a, action: ota.ecu.flash, when: [ param.image_digest == 1 ], verdict: ALLOW }"), /digest parameter/);
  assert.match(err("{ id: a, action: brake.disable, verdict: ALLOW }"), /unknown action/);
  assert.match(err("{ id: a, action: cabin.climate.set, verdict: ALLOW, reason: NOPE }"), /unknown reason NOPE/);
  assert.match(err("{ id: a, action: cabin.climate.set, verdict: BLOCK, interlock: [ speed_dkph == 0 ] }"), /meaningless on a BLOCK/);
  assert.match(err("{ id: a, action: cabin.climate.set, verdict: ALLOW, admin: true }"), /unknown key admin/);
  // the YAML trap that the shipped policy hit: an unquoted comma splits a flow list
  assert.match(err("{ id: a, action: adas.acc.set_speed, when: [ absdiff(param.target_kph, acc_target_kph) > 20 ], verdict: ALLOW }"), /cannot parse predicate "absdiff\(param.target_kph"/);
});
