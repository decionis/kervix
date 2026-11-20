// kxpolicy test: YAML fixtures ("given this vehicle state, this proposal must get
// this verdict / reason / rule"), evaluated by the vehicle's own C core (WASM)
// on the COMPILED policy. Also reports rules no fixture exercised.
import fs from "node:fs";
import path from "node:path";
import { parse } from "yaml";

import { compile } from "./compile.ts";
import { PolicyCore, type Proposal } from "./core.ts";

type Case = { name: string; telemetry?: Record<string, number | string>; propose: Proposal; env?: { ledger_ok?: boolean; age_ms?: number }; expect: { verdict?: string; reason?: string; rule?: string; gate?: string } };
type Fixture = { policy: string; base?: Record<string, number | string>; cases: Case[] };
export type TestReport = { file: string; policyHash: string; passed: number; failed: number; lines: string[]; uncovered: string[] };

export async function runFixture(file: string, core?: PolicyCore): Promise<TestReport> {
  const fx = parse(fs.readFileSync(file, "utf8")) as Fixture;
  const policyFile = path.resolve(path.dirname(file), fx.policy);
  const compiled = compile(fs.readFileSync(policyFile, "utf8"));
  const c = core ?? (await PolicyCore.create());
  const loaded = c.load(compiled.body);
  if (!loaded) throw new Error(`${policyFile}: the vehicle's loader rejects the compiled policy`);
  const lines: string[] = [];
  let passed = 0, failed = 0;
  const hit = new Set<string>();
  for (const k of fx.cases) {
    const got = c.evaluate(k.propose, { ...(fx.base ?? {}), ...(k.telemetry ?? {}) }, k.env);
    if (got.rule) hit.add(got.rule);
    const bad = (Object.keys(k.expect) as (keyof Case["expect"])[]).filter((f) => k.expect[f] !== got[f]);
    if (bad.length === 0) { passed++; lines.push(`PASS  ${k.name}: ${got.verdict} ${got.reason}${got.rule ? ` (${got.rule})` : ""}`); }
    else { failed++; lines.push(`FAIL  ${k.name}: ${bad.map((f) => `${f} expected ${k.expect[f]}, got ${got[f]}`).join("; ")}`); }
  }
  const ruleIds = ruleIdsOf(fs.readFileSync(policyFile, "utf8"));
  return { file, policyHash: loaded.hash, passed, failed, lines, uncovered: ruleIds.filter((r) => !hit.has(r)) };
}

function ruleIdsOf(yamlText: string): string[] {
  const doc = parse(yamlText) as { rules: { id: string }[] };
  return doc.rules.map((r) => r.id);
}
