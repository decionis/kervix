#!/usr/bin/env node
// kervix-agent: the vehicle's AI agent. Every vehicle action goes to Kervix on QNX
// through host/bridge (npm run bridge) and is decided there.
//
//   node host/agent/src/main.ts script scenarios/s1-cold.json [more.json...] [--auto-approve MS] [--pace MS]
//   node host/agent/src/main.ts live ["first utterance"]   (interactive; needs Claude API credentials)
//   env: KX_BRIDGE (default http://127.0.0.1:8787), KX_EFFORT (default medium)
import readline from "node:readline/promises";

import { LiveAgent, MODEL } from "./live.ts";
import { loadScenario, runScenario } from "./scripted.ts";
import { bridgeApi } from "./tools.ts";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
};
const api = bridgeApi(process.env.KX_BRIDGE ?? "http://127.0.0.1:8787");
const mode = args.shift();

if (mode === "script") {
  const auto = flag("--auto-approve");
  const pace = flag("--pace");
  let ok = true;
  for (const file of args) {
    const r = await runScenario(loadScenario(file), { api, autoApproveMs: auto === undefined ? undefined : Number(auto), pacingMs: pace ? Number(pace) : 0 });
    console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}: ${r.checks.map((c) => `${c.tool} ${(c.got as { verdict: string }).verdict}`).join(", ") || "no checks"}`);
    ok &&= r.ok;
  }
  process.exit(ok ? 0 : 1);
} else if (mode === "live") {
  const effort = (process.env.KX_EFFORT ?? "medium") as "low" | "medium" | "high";
  const agent = new LiveAgent({ api, effort });
  console.log(`live agent (${MODEL}, effort ${effort}); Ctrl-D to quit`);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let first: string | undefined = args.join(" ") || undefined;
  for (;;) {
    const line = first ?? (await rl.question("driver> ").catch(() => null));
    first = undefined;
    if (line === null) break;
    if (!line.trim()) continue;
    process.stdout.write("agent> ");
    await agent.say(line);
  }
  rl.close();
} else {
  console.log("usage: kervix-agent script <scenario.json...> [--auto-approve MS] [--pace MS]\n       kervix-agent live [\"utterance\"]");
  process.exit(2);
}
