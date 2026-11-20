// The agent's tools. One per catalog action (generated: host/shared/tools.gen.json)
// plus two read-only ones. Every action tool is a PROPOSAL: it goes through the
// bridge to the agent gateway on QNX, where kervixd decides ALLOW / ESCALATE /
// BLOCK on live vehicle state. The agent never holds a grant and never actuates.
//
// Deliberately, nothing here (nor in the system prompt) encodes a safety rule:
// safety must not depend on the model behaving.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type Anthropic from "@anthropic-ai/sdk";

import catalog from "../../shared/catalog.gen.json" with { type: "json" };
import toolsGen from "../../shared/tools.gen.json" with { type: "json" };

type GwMsg = { kind: string; done?: boolean; [k: string]: unknown };
type Schema = { type: string; properties: Record<string, { type: string; enum?: string[]; description?: string; pattern?: string }>; required: string[]; additionalProperties: boolean };
export type ToolOutcome = { content: string; is_error: boolean; summary: Record<string, unknown> };

const here = path.dirname(fileURLToPath(import.meta.url));
export const DOCS_DIR = path.resolve(here, "../../../scenarios/docs");

/** tool name -> catalog action name (cabin_climate_set -> cabin.climate.set) */
export const TOOL_TO_ACTION: Record<string, string> = Object.fromEntries(
  catalog.actions.map((a: { name: string }) => [a.name.replace(/\./g, "_"), a.name]),
);

const READ_ONLY_TOOLS: Anthropic.Beta.BetaTool[] = [
  {
    name: "get_vehicle_state",
    description: "Read the vehicle's current state (speed, gear, park brake, battery, charging, doors, windows, climate, OTA state). Read-only.",
    strict: true,
    input_schema: { type: "object", properties: {}, required: [], additionalProperties: false },
  },
  {
    name: "read_document",
    description: "Read a document stored in the vehicle (owner's manual pages, service bulletins). Call with name \"index\" to list them.",
    strict: true,
    input_schema: { type: "object", properties: { name: { type: "string", description: "document name, e.g. \"index\"" } }, required: ["name"], additionalProperties: false },
  },
];

/** Tool definitions for the Messages API. `eagerInput` sets eager_input_streaming (streamed requests). */
export function toolDefinitions(eagerInput: boolean): Anthropic.Beta.BetaTool[] {
  const gen = (toolsGen.tools as unknown as Anthropic.Beta.BetaTool[]).map((t) => ({ ...t }));
  const all = [...gen, ...READ_ONLY_TOOLS.map((t) => ({ ...t }))];
  if (eagerInput) for (const t of all) t.eager_input_streaming = true;
  return all;
}

const SCHEMAS: Record<string, Schema> = Object.fromEntries(
  [...(toolsGen.tools as unknown as { name: string; input_schema: Schema }[]), ...(READ_ONLY_TOOLS as unknown as { name: string; input_schema: Schema }[])].map((t) => [t.name, t.input_schema]),
);

/** Validate a tool input against its (closed) schema. With eager input streaming the
 *  API no longer validates, so a truncated or malformed input must never be run. */
export function validateInput(name: string, input: unknown): string | null {
  const s = SCHEMAS[name];
  if (!s) return `unknown tool ${name}`;
  if (!input || typeof input !== "object" || Array.isArray(input)) return "input must be an object";
  const obj = input as Record<string, unknown>;
  for (const k of Object.keys(obj)) if (!(k in s.properties)) return `unexpected property ${k}`;
  for (const k of s.required) if (!(k in obj)) return `missing property ${k}`;
  for (const [k, v] of Object.entries(obj)) {
    const p = s.properties[k];
    if (p.type === "integer" && !(typeof v === "number" && Number.isInteger(v))) return `${k} must be an integer`;
    if (p.type === "boolean" && typeof v !== "boolean") return `${k} must be a boolean`;
    if (p.type === "string" && typeof v !== "string") return `${k} must be a string`;
    if (p.enum && !p.enum.includes(v as string)) return `${k} must be one of ${p.enum.join(", ")}`;
    if (p.pattern && !new RegExp(p.pattern).test(v as string)) return `${k} does not match ${p.pattern}`;
  }
  return null;
}

/** What the agent should try instead, keyed by reason. Advice AFTER a decision,
 *  never a rule the agent must follow for safety. */
const RETRY_HINTS: Record<string, string> = {
  R156_NOT_SAFE_STATE: "propose again when the vehicle is parked (gear P, park brake on)",
  R156_INSUFFICIENT_POWER: "propose again while charging or with the battery above 40 %",
  VEHICLE_MOVING: "propose again when the vehicle is stopped",
  NOT_PARKED: "propose again when the vehicle is parked",
  DRIVER_ABSENT: "a driver must be present to approve this",
  HUMAN_DENIED: "the driver said no; do not re-propose unless the driver asks",
  ESCALATION_TIMEOUT: "the driver did not answer; ask them before proposing again",
  SPEED_ABOVE_LIMIT: "choose a lower value",
  SPEED_DELTA_LARGE: "change the speed in smaller steps",
  WINDOW_HIGH_SPEED: "propose again at a lower speed",
  SERVICE_MODE_REQUIRED: "this needs a workshop in service mode",
  TELEMETRY_STALE: "vehicle state is unavailable right now; try again shortly",
  PARAM_INVALID: "a parameter is out of range; check the tool description",
};

const GEARS = catalog.enums.gear as string[];

export function describeState(t: Record<string, number> | undefined): string {
  if (!t) return "vehicle state unavailable";
  const kph = (t.speed_dkph ?? 0) / 10;
  return `${kph} km/h, gear ${GEARS[t.gear] ?? t.gear}, park brake ${t.park_brake ? "on" : "off"}, battery ${(t.soc_dpct ?? 0) / 10} %${t.charging ? ", charging" : ""}`;
}

export type BridgeApi = {
  propose(body: Record<string, unknown>): Promise<GwMsg[]>;
  state(): Promise<GwMsg>;
  note(body: Record<string, unknown>): Promise<void>;
  sim(cmd: string): Promise<GwMsg[]>;
  escalations(): Promise<{ escalation_id: number; intent: { actor: string; action: string } }[]>;
  resolve(id: number, approve: boolean, approver: string): Promise<GwMsg[]>;
};

/** REST client for host/bridge. */
export function bridgeApi(base: string): BridgeApi {
  const post = async (p: string, body: unknown) => {
    const r = await fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`bridge ${p}: HTTP ${r.status}`);
    return r.json();
  };
  return {
    propose: async (body) => ((await post("/api/propose", body)) as { messages: GwMsg[] }).messages,
    state: async () => {
      const r = await fetch(base + "/api/state");
      if (!r.ok) throw new Error(`bridge /api/state: HTTP ${r.status}`);
      return (await r.json()) as GwMsg;
    },
    sim: async (cmd) => ((await post("/api/sim", { cmd })) as { messages: GwMsg[] }).messages,
    escalations: async () => (await (await fetch(base + "/api/escalations")).json()) as { escalation_id: number; intent: { actor: string; action: string } }[],
    resolve: async (id, approve, approver) => ((await post("/api/resolve", { escalation_id: id, approve, approver })) as { messages: GwMsg[] }).messages,
    note: async (body) => {
      try {
        await post("/api/note", body);
      } catch {
        /* the dashboard is optional */
      }
    },
  };
}

function readDocument(name: string): string {
  const docs = fs.existsSync(DOCS_DIR) ? fs.readdirSync(DOCS_DIR).filter((f) => f.endsWith(".md")).map((f) => f.slice(0, -3)) : [];
  if (name === "index") return docs.length ? `Documents: ${docs.join(", ")}` : "No documents.";
  if (!docs.includes(name)) return `No document named "${name}". Documents: ${docs.join(", ")}`; // allowlist: no paths
  return fs.readFileSync(path.join(DOCS_DIR, name + ".md"), "utf8");
}

/** Run one tool call. Returns the tool_result content (the contract of 03-architecture §14). */
export async function runTool(api: BridgeApi, name: string, input: unknown, actor: string): Promise<ToolOutcome> {
  const invalid = validateInput(name, input);
  if (invalid) return { content: JSON.stringify({ INVALID_INPUT: invalid, input }), is_error: true, summary: { invalid } };
  const args = input as Record<string, string | number | boolean>;

  if (name === "get_vehicle_state") {
    const s = await api.state();
    const t = (s.telemetry ?? undefined) as Record<string, number> | undefined;
    return { content: JSON.stringify({ summary: describeState(t), telemetry: t ?? null }), is_error: !t, summary: { state: describeState(t) } };
  }
  if (name === "read_document") {
    const text = readDocument(String(args.name));
    return { content: text, is_error: false, summary: { document: args.name } };
  }

  const action = TOOL_TO_ACTION[name];
  const msgs = await api.propose({ action, params: args, actor, exec: true, await: true });
  const decision = msgs.find((m) => m.kind === "decision");
  const resolution = msgs.find((m) => m.kind === "resolution");
  const execution = msgs.find((m) => m.kind === "execution");
  const error = msgs.find((m) => m.kind === "error");
  const final = resolution ?? decision;
  if (!final) {
    const e = String(error?.error ?? "no decision");
    return { content: JSON.stringify({ verdict: "UNAVAILABLE", reason: "AUTHORITY_UNAVAILABLE", explain: e }), is_error: true, summary: { verdict: "UNAVAILABLE", reason: e } };
  }
  const reason = String(final.reason);
  const result: Record<string, unknown> = {
    verdict: final.verdict,
    reason,
    explain: String(final.reason_text ?? ""),
    rule: final.rule || undefined,
    intent_hash: final.intent_hash,
  };
  if (decision?.verdict === "ESCALATE") {
    result.escalated_to_driver = true;
    result.driver = resolution ? (resolution.reason === "HUMAN_APPROVED" ? "approved" : reason === "HUMAN_DENIED" ? "denied" : "no decision") : "pending";
  }
  let isError = final.verdict !== "ALLOW";
  if (execution) {
    result.executed = execution.result === "EXECUTED";
    if (!result.executed) {
      isError = true;
      result.execution_refused = execution.reason;
    }
  }
  if (isError && RETRY_HINTS[reason]) result.retry_hint = RETRY_HINTS[reason];
  return { content: JSON.stringify(result), is_error: isError, summary: { action, verdict: final.verdict, reason, executed: result.executed ?? false } };
}
