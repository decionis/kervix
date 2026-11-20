// Scripted mode: replay a recorded agent transcript (scenarios/*.json) against
// the LIVE target. Only the language model is recorded; every proposal still
// goes to kervixd on QNX and every verdict is real. If a verdict differs from
// the recording, the run reports it and fails: the transcript no longer
// matches reality (used for the video, CI and judges without an API key).
import fs from "node:fs";

import { runTool, validateInput, type BridgeApi } from "./tools.ts";

export type ScriptTurn = {
  thinking?: string;
  text?: string;
  tool?: { name: string; input: Record<string, unknown> };
  expect?: { verdict?: string; reason?: string; executed?: boolean };
};
export type Scenario = {
  name: string;
  title: string;
  setup?: { sim?: string; wait?: { field: string; equals: number; timeout_ms?: number } }[];
  user: string;
  turns: ScriptTurn[];
};
export type ScriptResult = { name: string; ok: boolean; checks: { tool: string; expected: unknown; got: unknown; ok: boolean }[] };

export function loadScenario(file: string): Scenario {
  const s = JSON.parse(fs.readFileSync(file, "utf8")) as Scenario;
  if (!s.name || !s.user || !Array.isArray(s.turns)) throw new Error(`${file}: not a scenario`);
  for (const t of s.turns) if (t.tool) {
    const bad = validateInput(t.tool.name, t.tool.input);
    if (bad) throw new Error(`${file}: ${t.tool.name}: ${bad}`);
  }
  return s;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export type ScriptOptions = {
  api: BridgeApi;
  actor?: string;
  /** approve the agent's own escalations after this many ms (headless runs); undefined = a human decides */
  autoApproveMs?: number;
  /** pause between turns so a viewer can follow (ms) */
  pacingMs?: number;
  log?: (s: string) => void;
};

export async function runScenario(s: Scenario, o: ScriptOptions): Promise<ScriptResult> {
  const actor = o.actor ?? "agent:cabin-copilot";
  const log = o.log ?? ((l) => console.log(l));
  const note = (body: Record<string, unknown>) => o.api.note({ source: "agent", mode: "scripted", scenario: s.name, ...body });
  const result: ScriptResult = { name: s.name, ok: true, checks: [] };

  for (const st of s.setup ?? []) {
    if (st.sim) await o.api.sim(st.sim);
    if (st.wait) {
      const t0 = Date.now();
      for (;;) {
        const tel = (await o.api.state()).telemetry as Record<string, number> | undefined;
        if (tel && tel[st.wait.field] === st.wait.equals) break;
        if (Date.now() - t0 > (st.wait.timeout_ms ?? 30000)) throw new Error(`setup: ${st.wait.field} never became ${st.wait.equals}`);
        await sleep(250);
      }
    }
  }
  log(`== ${s.title}`);
  log(`driver> ${s.user}`);
  await note({ role: "user", text: s.user });

  for (const t of s.turns) {
    if (o.pacingMs) await sleep(o.pacingMs);
    if (t.thinking) { log(`  (thinking) ${t.thinking}`); await note({ role: "thinking", text: t.thinking }); }
    if (t.text) { log(`agent> ${t.text}`); await note({ role: "assistant", text: t.text }); }
    if (!t.tool) continue;
    log(`  tool ${t.tool.name} ${JSON.stringify(t.tool.input)}`);
    await note({ role: "tool_call", tool: t.tool.name, input: t.tool.input });
    let approving = true;
    const approver = o.autoApproveMs === undefined ? null : (async () => {
      while (approving) {
        const pending = (await o.api.escalations()).filter((e) => e.intent.actor === actor);
        if (pending.length) {
          await sleep(o.autoApproveMs ?? 0);
          for (const e of pending) await o.api.resolve(e.escalation_id, true, "hmi:auto-approve(scripted run)");
          return;
        }
        await sleep(100);
      }
    })();
    const r = await runTool(o.api, t.tool.name, t.tool.input, actor);
    approving = false;
    await approver;
    await note({ role: "tool_result", tool: t.tool.name, is_error: r.is_error, ...r.summary });
    log(`  -> ${r.content}`);
    if (t.expect) {
      const got = r.summary;
      const ok = (t.expect.verdict === undefined || got.verdict === t.expect.verdict) &&
        (t.expect.reason === undefined || got.reason === t.expect.reason) &&
        (t.expect.executed === undefined || got.executed === t.expect.executed);
      result.checks.push({ tool: t.tool.name, expected: t.expect, got, ok });
      if (!ok) {
        result.ok = false;
        log(`  !! the live verdict differs from the recording: expected ${JSON.stringify(t.expect)}; the transcript stops here`);
        await note({ role: "mismatch", expected: t.expect, got });
        break;
      }
    }
  }
  return result;
}
