// The vehicle's signed ledger, mirrored on the host for the ledger explorer:
// fetched incrementally through the observer gateway (read-only; ledger_info,
// ledger, policy ops), verified with exactly the checks of kervix-verify
// (host/verify/verify-lib.mjs) on demand.
import { createHash } from "node:crypto";

import { oneShot, type GwMsg } from "./gateway.ts";
// @ts-expect-error: plain ESM module without type declarations
import { verifyDossier } from "../../verify/verify-lib.mjs";

export type LedgerRecord = { seq: number; capsule_id: string; text: string; envelope: string };
export type LedgerSummary = {
  seq: number; capsule_id: string; time: string; event: string; verdict: string | null; verdict_class: string | null;
  reason: string; rule: string | null; action: string | null; actor: string | null; policy_hash: string; human: boolean;
};
export type LedgerInfo = { records: number; first_seq: number; last_seq: number; kid: string | null; policies: string[]; synced_at: number };

const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

export function summarize(r: LedgerRecord): LedgerSummary {
  const c = JSON.parse(r.text);
  const k = c.evidence?.kervix ?? {};
  return {
    seq: r.seq, capsule_id: r.capsule_id, time: c.timestamp, event: k.event, verdict: k.verdict ?? null,
    verdict_class: c.disposition?.verdict_class ?? null, reason: k.reason, rule: k.rule_id ?? null,
    action: k.intent?.action ?? null, actor: k.intent?.actor ?? null, policy_hash: k.policy_hash, human: c.disposition?.human_disposed === true,
  };
}

/** Change the last digit of a capsule's timestamp (back-dating a record by a few
 *  milliseconds): still valid JSON, chain untouched, so only that capsule is caught. */
export function tamper(text: string): string {
  const k = text.indexOf('"timestamp":"');
  const z = text.indexOf("Z", k);
  const i = z - 1;
  const d = Number(text[i]);
  return text.slice(0, i) + String((d + 9) % 10) + text.slice(i + 1);
}

export class LedgerMirror {
  records: LedgerRecord[] = [];
  jwk: string | null = null;
  policies = new Map<string, Buffer>();
  info: LedgerInfo = { records: 0, first_seq: 0, last_seq: 0, kid: null, policies: [], synced_at: 0 };
  private syncing: Promise<boolean> | null = null;
  private readonly host: string;
  private readonly port: number;

  constructor(host: string, observerPort: number) {
    this.host = host;
    this.port = observerPort;
  }

  private async op(req: Record<string, unknown>): Promise<GwMsg[]> {
    return oneShot(this.host, this.port, req as { op: string }, { timeoutMs: 60_000 });
  }

  /** Bring the mirror up to date. Resolves true if anything changed. */
  sync(): Promise<boolean> {
    if (!this.syncing) this.syncing = this.doSync().finally(() => (this.syncing = null));
    return this.syncing;
  }

  private async doSync(): Promise<boolean> {
    const info = (await this.op({ op: "ledger_info" })).at(-1) as GwMsg & { records: number; first_seq: number; last_seq: number; jwk: string; policies: string[] };
    let changed = false;
    const have = this.records.at(-1)?.seq ?? 0;
    // a fresh ledger on the vehicle (re-provisioned) or a gap: start over
    if (info.last_seq < have || (this.records.length && this.records[0].seq !== info.first_seq)) {
      this.records = [];
      this.policies.clear();
      changed = true;
    }
    let next = (this.records.at(-1)?.seq ?? info.first_seq - 1) + 1;
    while (next <= info.last_seq) {
      const msgs = await this.op({ op: "ledger", from_seq: next, max: 200 });
      const recs = msgs.filter((m) => m.kind === "record") as unknown as { seq: number; capsule_id: string; capsule: string; envelope: string }[];
      if (!recs.length) break;
      for (const r of recs) {
        if (r.seq !== next) throw new Error(`ledger gap: expected seq ${next}, got ${r.seq}`);
        this.records.push({ seq: r.seq, capsule_id: r.capsule_id, text: r.capsule, envelope: r.envelope });
        next++;
      }
      changed = true;
    }
    for (const name of info.policies) {
      if (this.policies.has(name)) continue;
      const msgs = await this.op({ op: "policy", name });
      const parts = msgs.filter((m) => m.kind === "policy_chunk").sort((a, b) => Number(a.offset) - Number(b.offset));
      this.policies.set(name, Buffer.concat(parts.map((p) => Buffer.from(String(p.data), "base64url"))));
      changed = true;
    }
    this.jwk = info.jwk;
    let kid: string | null = null;
    try { kid = JSON.parse(info.jwk).keys[0].kid; } catch { /* no key yet */ }
    this.info = { records: this.records.length, first_seq: this.records[0]?.seq ?? 0, last_seq: this.records.at(-1)?.seq ?? 0, kid, policies: [...this.policies.keys()], synced_at: Date.now() };
    return changed;
  }

  /** Verify the mirror with the kervix-verify checks; optionally after tampering with one capsule. */
  async verify(opts: { tamperSeq?: number } = {}): Promise<Record<string, unknown>> {
    if (!this.records.length || !this.jwk) throw new Error("the ledger is empty");
    const lines = this.records.map((r) => (r.seq === opts.tamperSeq ? tamper(r.text) : r.text));
    const caps = Buffer.from(lines.join("\n") + "\n");
    const envs = Buffer.from(this.records.map((r) => r.envelope).join("\n") + "\n");
    const jwk = Buffer.from(this.jwk + "\n");
    const files = new Map<string, Buffer>([["capsules.jsonl", caps], ["envelopes.txt", envs], ["vehicle.jwk.json", jwk]]);
    const listed: Record<string, string> = { "capsules.jsonl": `sha256:${sha(caps)}`, "envelopes.txt": `sha256:${sha(envs)}`, "vehicle.jwk.json": `sha256:${sha(jwk)}` };
    for (const [name, b] of this.policies) {
      files.set(`policies/${name}.kxp`, b);
      listed[`policies/${name}.kxp`] = `sha256:${sha(b)}`;
    }
    // the manifest is the vehicle's head as fetched (records, range, head id): a tampered
    // capsule keeps its recorded id, so the verifier sees content that no longer matches it
    files.set("manifest.json", Buffer.from(JSON.stringify({
      files: listed, first_seq: this.records[0].seq, format: "kervix.dossier/1", head_capsule_id: this.records.at(-1)!.capsule_id,
      last_seq: this.records.at(-1)!.seq, records: this.records.length,
    })));
    const t0 = Date.now();
    const summary = await verifyDossier({ files });
    return { ...summary, tampered_seq: opts.tamperSeq ?? null, elapsed_ms: Date.now() - t0 };
  }
}
