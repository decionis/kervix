#!/usr/bin/env node
// Kervix codegen: catalog/catalog.yaml -> C header + C tables + TS constants + tool schemas.
// Usage: node tools/codegen/codegen.mjs [--check]
//   --check  exit 1 if any generated file is out of date (used in CI)
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CATALOG = join(ROOT, "catalog", "catalog.yaml");
const OUT = {
  cHeader: join(ROOT, "target", "include", "kervix", "catalog_gen.h"),
  cSource: join(ROOT, "target", "libkxcore", "src", "catalog_gen.c"),
  ts: join(ROOT, "host", "shared", "src", "catalog.gen.ts"),
  tools: join(ROOT, "host", "shared", "tools.gen.json"),
};

const MAX_PARAMS = 6; // must match KX_MAX_PARAMS in abi.h
const IRREVERSIBILITY = ["two_way", "one_way_recoverable", "one_way_consequential", "one_way_terminal"];
const SAFETY = ["qm", "safety"];
const CTYPES = { int32: [-2147483648, 2147483647], int16: [-32768, 32767], uint8: [0, 255] };
const PARAM_TYPES = ["int", "enum", "bool", "digest"];
const NAME_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const IDENT_RE = /^[a-z][a-z0-9_]*$/;

// ---------- load + validate ----------
const raw = readFileSync(CATALOG, "utf8");
const catalogSha = createHash("sha256").update(raw).digest("hex");
const cat = parse(raw);
const errors = [];
const fail = (m) => errors.push(m);

if (cat.version !== 1) fail(`unsupported catalog version ${cat.version}`);
const enums = cat.enums ?? {};
for (const [k, vals] of Object.entries(enums)) {
  if (!IDENT_RE.test(k)) fail(`enum name ${k}`);
  if (!Array.isArray(vals) || vals.length === 0 || vals.length > 255) fail(`enum ${k} values`);
  if (new Set(vals).size !== vals.length) fail(`enum ${k} has duplicates`);
}

const tfields = Object.entries(cat.telemetry ?? {}).map(([name, f]) => {
  if (!IDENT_RE.test(name)) fail(`telemetry field ${name}`);
  if (!CTYPES[f.ctype]) fail(`telemetry ${name}: ctype ${f.ctype}`);
  let min = f.min, max = f.max;
  if (f.enum) {
    if (!enums[f.enum]) fail(`telemetry ${name}: unknown enum ${f.enum}`);
    min = 0; max = (enums[f.enum]?.length ?? 1) - 1;
  }
  if (!Number.isInteger(min) || !Number.isInteger(max) || min > max) fail(`telemetry ${name}: bad range`);
  const [lo, hi] = CTYPES[f.ctype] ?? [0, 0];
  if (min < lo || max > hi) fail(`telemetry ${name}: range exceeds ${f.ctype}`);
  return { name, ctype: f.ctype, vss: f.vss ?? null, min, max, enumName: f.enum ?? null, note: f.note ?? "" };
});

const paramKeys = []; // global, first-appearance order; index+1 = key id
const actions = (cat.actions ?? []).map((a) => {
  if (!Number.isInteger(a.id) || a.id < 1 || a.id > 65535) fail(`action ${a.name}: id`);
  if (!NAME_RE.test(a.name ?? "")) fail(`action name ${a.name}`);
  if (!IRREVERSIBILITY.includes(a.irreversibility)) fail(`action ${a.name}: irreversibility`);
  if (!SAFETY.includes(a.safety)) fail(`action ${a.name}: safety`);
  const params = Object.entries(a.params ?? {}).map(([pname, p]) => {
    if (!IDENT_RE.test(pname)) fail(`action ${a.name}: param ${pname}`);
    if (!PARAM_TYPES.includes(p.type)) fail(`action ${a.name}.${pname}: type ${p.type}`);
    let min = 0, max = 0;
    if (p.type === "int") { min = p.min; max = p.max; }
    if (p.type === "bool") { min = 0; max = 1; }
    if (p.type === "enum") {
      if (!enums[p.enum]) fail(`action ${a.name}.${pname}: unknown enum ${p.enum}`);
      min = 0; max = (enums[p.enum]?.length ?? 1) - 1;
    }
    if (p.type !== "digest" && (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min > max)) {
      fail(`action ${a.name}.${pname}: bad range`);
    }
    if (!paramKeys.includes(pname)) paramKeys.push(pname);
    return { name: pname, type: p.type, min, max, enumName: p.enum ?? null, doc: p.doc ?? "" };
  });
  if (params.length > MAX_PARAMS) fail(`action ${a.name}: more than ${MAX_PARAMS} params`);
  if (params.filter((p) => p.type === "digest").length > 1) fail(`action ${a.name}: at most one digest param`);
  return {
    id: a.id, name: a.name, summary: a.summary ?? "", irreversibility: a.irreversibility,
    safety: a.safety, privacy: !!a.privacy, params,
  };
});
const dupe = (arr, key, what) => {
  const seen = new Set();
  for (const x of arr) { if (seen.has(x[key])) fail(`duplicate ${what} ${x[key]}`); seen.add(x[key]); }
};
dupe(actions, "id", "action id"); dupe(actions, "name", "action name");
const reasons = cat.reasons ?? [];
dupe(reasons, "id", "reason id"); dupe(reasons, "name", "reason name");
for (const r of reasons) if (!/^[A-Z][A-Z0-9_]*$/.test(r.name) || !Number.isInteger(r.id) || r.id < 0 || r.id > 65535) fail(`reason ${r.name}`);
if (!reasons.some((r) => r.id === 0 && r.name === "OK")) fail("reason 0 must be OK");

if (errors.length) {
  console.error("catalog.yaml is invalid:\n  - " + errors.join("\n  - "));
  process.exit(2);
}

// ---------- helpers ----------
const C = (s) => s.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
const cstr = (s) => JSON.stringify(s ?? ""); // ASCII-safe enough for our catalog (validated identifiers + notes)
const toolName = (n) => n.replace(/\./g, "_"); // Claude tool names: ^[a-zA-Z0-9_-]{1,64}$
const banner = (c) => `${c} GENERATED by tools/codegen from catalog/catalog.yaml — DO NOT EDIT.\n${c} catalog sha256: ${catalogSha}\n`;
const maxActionId = Math.max(...actions.map((a) => a.id));

// ---------- C header ----------
let h = `/*\n${banner(" *")} */\n#ifndef KERVIX_CATALOG_GEN_H\n#define KERVIX_CATALOG_GEN_H\n\n#include <stdint.h>\n\n`;
h += `#define KX_CATALOG_VERSION ${cat.version}\n#define KX_CATALOG_SHA256 "${catalogSha}"\n\n`;
for (const [k, vals] of Object.entries(enums)) {
  h += `typedef enum {\n${vals.map((v, i) => `    KX_${C(k)}_${C(v)} = ${i},`).join("\n")}\n    KX_${C(k)}__COUNT = ${vals.length}\n} kx_${k}_t;\n\n`;
}
h += `typedef enum {\n${IRREVERSIBILITY.map((v, i) => `    KX_IRR_${C(v)} = ${i},`).join("\n")}\n} kx_irreversibility_t;\n\n`;
h += `typedef enum { KX_SAFETY_QM = 0, KX_SAFETY_SAFETY = 1 } kx_safety_t;\n\n`;
h += `typedef enum { KX_PT_INT = 0, KX_PT_ENUM = 1, KX_PT_BOOL = 2, KX_PT_DIGEST = 3 } kx_param_type_t;\n\n`;
h += `/* Telemetry fields: kx_telemetry_t.v[] is indexed by these. */\ntypedef enum {\n${tfields.map((f, i) => `    KX_TF_${C(f.name)} = ${i},`).join("\n")}\n    KX_TF__COUNT = ${tfields.length}\n} kx_tfield_t;\n\n`;
h += `/* Actions (ids are append-only). */\ntypedef enum {\n    KX_ACT_NONE = 0,\n${actions.map((a) => `    KX_ACT_${C(a.name)} = ${a.id},`).join("\n")}\n} kx_action_id_t;\n#define KX_ACTION_COUNT ${actions.length}\n#define KX_ACTION_MAX_ID ${maxActionId}\n\n`;
h += `/* Parameter keys (global namespace across actions). */\ntypedef enum {\n    KX_P_NONE = 0,\n${paramKeys.map((p, i) => `    KX_P_${C(p)} = ${i + 1},`).join("\n")}\n} kx_param_key_t;\n#define KX_PARAM_KEY_COUNT ${paramKeys.length + 1}\n\n`;
h += `/* Reason codes (append-only). */\ntypedef enum {\n${reasons.map((r) => `    KX_R_${r.name} = ${r.id},`).join("\n")}\n} kx_reason_t;\n#define KX_REASON_COUNT ${reasons.length}\n\n`;
h += `#define KX_CATALOG_MAX_PARAMS ${MAX_PARAMS}\n\n`;
h += `typedef struct {
    uint16_t    key;        /* kx_param_key_t */
    uint8_t     type;       /* kx_param_type_t */
    int64_t     min, max;   /* inclusive; unused for DIGEST */
    const char *name;
    const char *const *enum_values; /* ENUM only, else NULL */
} kx_param_spec_t;

typedef struct {
    uint16_t        id;
    const char     *name;
    uint8_t         irreversibility; /* kx_irreversibility_t */
    uint8_t         safety;          /* kx_safety_t */
    uint8_t         privacy;
    uint8_t         n_params;
    kx_param_spec_t params[KX_CATALOG_MAX_PARAMS];
} kx_action_spec_t;

typedef struct {
    const char *name;
    const char *vss;     /* COVESA VSS path, or NULL for Kervix extension */
    int32_t     min, max;
} kx_tfield_spec_t;

typedef struct {
    uint16_t    id;
    const char *name;
    const char *text;
} kx_reason_spec_t;

extern const kx_action_spec_t kx_catalog_actions[KX_ACTION_COUNT];
extern const kx_tfield_spec_t kx_catalog_tfields[KX_TF__COUNT];
extern const kx_reason_spec_t kx_catalog_reasons[KX_REASON_COUNT];
extern const char *const      kx_catalog_param_names[KX_PARAM_KEY_COUNT];
extern const char *const      kx_irreversibility_names[4];
${Object.keys(enums).map((k) => `extern const char *const      kx_enum_${k}[KX_${C(k)}__COUNT];`).join("\n")}

/* O(1) lookups; return NULL when unknown. */
const kx_action_spec_t *kx_catalog_action(uint16_t id);
const kx_reason_spec_t *kx_catalog_reason(uint16_t id);
const kx_param_spec_t  *kx_catalog_param(const kx_action_spec_t *a, uint16_t key);

#endif /* KERVIX_CATALOG_GEN_H */
`;

// ---------- C source ----------
let c = `/*\n${banner(" *")} */\n#include <stddef.h>\n#include "kervix/catalog_gen.h"\n\n`;
for (const [k, vals] of Object.entries(enums)) {
  c += `const char *const kx_enum_${k}[KX_${C(k)}__COUNT] = { ${vals.map(cstr).join(", ")} };\n`;
}
c += `\nconst char *const kx_irreversibility_names[4] = { ${IRREVERSIBILITY.map(cstr).join(", ")} };\n\n`;
c += `const char *const kx_catalog_param_names[KX_PARAM_KEY_COUNT] = { NULL, ${paramKeys.map(cstr).join(", ")} };\n\n`;
c += `const kx_action_spec_t kx_catalog_actions[KX_ACTION_COUNT] = {\n`;
for (const a of actions) {
  const ps = a.params.map((p) =>
    `{ KX_P_${C(p.name)}, KX_PT_${C(p.type)}, ${p.min}LL, ${p.max}LL, ${cstr(p.name)}, ${p.enumName ? `kx_enum_${p.enumName}` : "NULL"} }`);
  c += `    { ${a.id}, ${cstr(a.name)}, KX_IRR_${C(a.irreversibility)}, KX_SAFETY_${C(a.safety)}, ${a.privacy ? 1 : 0}, ${a.params.length},\n      { ${ps.join(",\n        ") || "{ 0 }"} } },\n`;
}
c += `};\n\n`;
c += `const kx_tfield_spec_t kx_catalog_tfields[KX_TF__COUNT] = {\n${tfields.map((f) => `    { ${cstr(f.name)}, ${f.vss ? cstr(f.vss) : "NULL"}, ${f.min}, ${f.max} },`).join("\n")}\n};\n\n`;
c += `const kx_reason_spec_t kx_catalog_reasons[KX_REASON_COUNT] = {\n${reasons.map((r) => `    { ${r.id}, ${cstr(r.name)}, ${cstr(r.text)} },`).join("\n")}\n};\n\n`;
// dense index tables for O(1) lookup
const actIdx = new Array(maxActionId + 1).fill(-1);
actions.forEach((a, i) => (actIdx[a.id] = i));
const maxReason = Math.max(...reasons.map((r) => r.id));
const rIdx = new Array(maxReason + 1).fill(-1);
reasons.forEach((r, i) => (rIdx[r.id] = i));
c += `static const int16_t kx_action_index[${maxActionId + 1}] = { ${actIdx.join(", ")} };\n`;
c += `static const int16_t kx_reason_index[${maxReason + 1}] = { ${rIdx.join(", ")} };\n\n`;
c += `const kx_action_spec_t *kx_catalog_action(uint16_t id) {
    if (id > ${maxActionId} || kx_action_index[id] < 0) return NULL;
    return &kx_catalog_actions[kx_action_index[id]];
}

const kx_reason_spec_t *kx_catalog_reason(uint16_t id) {
    if (id > ${maxReason} || kx_reason_index[id] < 0) return NULL;
    return &kx_catalog_reasons[kx_reason_index[id]];
}

const kx_param_spec_t *kx_catalog_param(const kx_action_spec_t *a, uint16_t key) {
    if (a == NULL) return NULL;
    for (uint8_t i = 0; i < a->n_params && i < KX_CATALOG_MAX_PARAMS; i++) {
        if (a->params[i].key == key) return &a->params[i];
    }
    return NULL;
}
`;

// ---------- TS ----------
const tsCatalog = {
  version: cat.version, sha256: catalogSha, enums,
  telemetry: tfields.map(({ name, ctype, vss, min, max, enumName, note }) => ({ name, ctype, vss, min, max, enum: enumName, note })),
  actions: actions.map((a) => ({ ...a, tool: toolName(a.name), effectType: `vehicle.${a.name}`, params: a.params.map((p) => ({ ...p, key: paramKeys.indexOf(p.name) + 1 })) })),
  paramKeys: ["", ...paramKeys],
  reasons,
};
let ts = `${banner("//")}\n/* eslint-disable */\nexport const catalog = ${JSON.stringify(tsCatalog, null, 2)} as const;\n\n`;
ts += `export type ActionName = (typeof catalog.actions)[number]["name"];\n`;
ts += `export type ReasonName = (typeof catalog.reasons)[number]["name"];\n`;
ts += `export type TelemetryField = (typeof catalog.telemetry)[number]["name"];\n`;
ts += `export type Verdict = "ALLOW" | "ESCALATE" | "BLOCK";\n`;

// ---------- tool schemas (Claude Messages API / MCP), strict ----------
// Ranges go into descriptions rather than minimum/maximum: Kervix enforces
// ranges authoritatively, so an out-of-range proposal becomes a visible BLOCK.
const tools = actions.map((a) => {
  const properties = {};
  for (const p of a.params) {
    if (p.type === "int") properties[p.name] = { type: "integer", description: `${p.doc || p.name}. Allowed range ${p.min}..${p.max}.` };
    if (p.type === "bool") properties[p.name] = { type: "boolean", description: p.doc || p.name };
    if (p.type === "enum") properties[p.name] = { type: "string", enum: enums[p.enumName], description: p.doc || p.name };
    if (p.type === "digest") properties[p.name] = { type: "string", description: `${p.doc || p.name}. Format: sha256:<64 lowercase hex>.` };
  }
  return {
    name: toolName(a.name),
    description: `${a.summary} Every call is a PROPOSAL evaluated by the vehicle's execution authority (Kervix), which may ALLOW, ESCALATE to the driver, or BLOCK it with a reason. Irreversibility: ${a.irreversibility}.`,
    strict: true,
    input_schema: { type: "object", properties, required: a.params.map((p) => p.name), additionalProperties: false },
  };
});
const toolsJson = JSON.stringify({ catalog_sha256: catalogSha, tools }, null, 2) + "\n";

// ---------- write / check ----------
const outputs = [[OUT.cHeader, h], [OUT.cSource, c], [OUT.ts, ts], [OUT.tools, toolsJson]];
const check = process.argv.includes("--check");
let stale = 0;
for (const [path, content] of outputs) {
  const cur = existsSync(path) ? readFileSync(path, "utf8") : null;
  if (cur === content) continue;
  if (check) { console.error(`stale: ${relative(ROOT, path)}`); stale++; continue; }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  console.log(`wrote ${relative(ROOT, path)}`);
}
if (check && stale) { console.error("run `npm run codegen`"); process.exit(1); }
console.log(`catalog v${cat.version}: ${actions.length} actions, ${tfields.length} telemetry fields, ${reasons.length} reasons, ${paramKeys.length} param keys`);
