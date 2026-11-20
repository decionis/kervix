// The ledger explorer: every signed capsule the vehicle recorded, and a Verify
// button that runs exactly the kervix-verify checks (in the bridge) on the
// mirrored ledger. "Edit this capsule" verifies a copy with one record
// back-dated by a few milliseconds: the failure lands on that capsule.
import { useCallback, useEffect, useMemo, useState } from "react";

import { Badge } from "./panels.tsx";

type Item = {
  seq: number; capsule_id: string; time: string; event: string; verdict: string | null; verdict_class: string | null;
  reason: string; rule: string | null; action: string | null; actor: string | null; policy_hash: string; human: boolean;
};
type Info = { records: number; first_seq: number; last_seq: number; kid: string | null; policies: string[] };
type Finding = { check: string; where: string; message: string };
type Summary = {
  verified: boolean; capsules: number; epochs: number; findings: Finding[]; executed: number; elapsed_ms: number; tampered_seq: number | null;
  replay: { match: number; mismatch: number; unknown_policy: number; k3: number; policies: string[] };
  policies: { hash: string; author: string; approver: string }[]; vehicle_key: string;
};

const FILTERS: Record<string, (i: Item) => boolean> = {
  all: () => true,
  decisions: (i) => i.event === "decision",
  actions: (i) => i.event === "effect" || i.event === "grant_refused" || i.event === "grant_expired",
  human: (i) => i.event === "escalation_resolved" || i.event === "policy_activated",
  system: (i) => i.event === "epoch" || i.event === "policy_activated",
};
const EVENT_LABEL: Record<string, string> = {
  epoch: "authority started", decision: "decision", effect: "actuation", escalation_resolved: "driver decision",
  grant_refused: "grant refused", grant_expired: "grant expired", policy_activated: "policy activated",
};

function outcome(i: Item): string | null {
  if (i.event === "decision") return i.verdict;
  if (i.event === "effect") return i.verdict_class === "executed" ? "EXECUTED" : "REFUSED";
  if (i.event === "escalation_resolved") return i.verdict;
  if (i.event === "grant_refused" || i.event === "grant_expired") return "REFUSED";
  return null;
}

const CHECKS: [string, string][] = [
  ["manifest", "records, range and head match"],
  ["key", "one Ed25519 vehicle key; kid = its thumbprint"],
  ["capsules", "canonical, self-identifying, AAC draft-04 Class 1"],
  ["signatures", "every envelope signed by the pinned vehicle key"],
  ["chain", "each capsule chained to the previous one, no gap"],
  ["semantics", "no actuation without authority, none twice"],
  ["policy", "signed policies: author + approver signatures"],
  ["replay", "every decision re-run on the vehicle's own C policy core"],
];

export function LedgerView({ info }: { info: Info | null }) {
  const [items, setItems] = useState<Item[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [detail, setDetail] = useState<{ capsule: unknown; envelope: string } | null>(null);
  const [filter, setFilter] = useState("all");
  const [result, setResult] = useState<Summary | null>(null);
  const [busy, setBusy] = useState(false);

  const last = items.at(-1)?.seq ?? 0;
  useEffect(() => {
    if (!info || info.last_seq === last) return;
    const reset = info.last_seq < last;
    void fetch(`/api/ledger?after=${reset ? 0 : last}`).then((r) => r.json()).then((d: { items: Item[] }) =>
      setItems((prev) => (reset ? d.items : [...prev, ...d.items])));
  }, [info, last]);

  useEffect(() => {
    if (sel === null) return setDetail(null);
    void fetch(`/api/ledger/${sel}`).then((r) => r.json()).then(setDetail);
  }, [sel]);

  const verify = useCallback(async (tamper?: number) => {
    setBusy(true);
    try {
      const r = await fetch("/api/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(tamper ? { tamper_seq: tamper } : {}) });
      setResult((await r.json()) as Summary);
    } finally {
      setBusy(false);
    }
  }, []);

  const flagged = useMemo(() => new Set((result?.findings ?? []).map((f) => Number(/#(\d+)/.exec(f.where)?.[1] ?? 0) + (info?.first_seq ?? 1) - 1)), [result, info]);
  const shown = items.filter(FILTERS[filter]).slice(-400).reverse();
  const selItem = items.find((i) => i.seq === sel);

  return (
    <main className="ledger">
      <section className="col">
        <div className="card">
          <h2>
            Signed ledger <span className="sub">{info ? `${info.records} capsules · seq ${info.first_seq}..${info.last_seq} · vehicle key ${info.kid?.slice(0, 12) ?? "?"}… · ${info.policies.length} signed polic${info.policies.length === 1 ? "y" : "ies"}` : "waiting for the vehicle…"}</span>
          </h2>
          <div className="world">
            {Object.keys(FILTERS).map((f) => (
              <button key={f} className={`btn ${filter === f ? "on" : ""}`} onClick={() => setFilter(f)}>{f}</button>
            ))}
          </div>
        </div>
        <div className="card list">
          <table className="ledger-table">
            <thead>
              <tr><th>#</th><th>time</th><th>event</th><th>outcome</th><th>action</th><th>reason · rule</th></tr>
            </thead>
            <tbody>
              {shown.map((i) => (
                <tr key={i.seq} className={`${sel === i.seq ? "sel" : ""} ${flagged.has(i.seq) ? "flag" : ""}`} onClick={() => setSel(i.seq)}>
                  <td>{i.seq}</td>
                  <td>{new Date(i.time).toLocaleTimeString([], { hour12: false })}</td>
                  <td>{EVENT_LABEL[i.event] ?? i.event}{i.human ? " 🧑" : ""}</td>
                  <td>{outcome(i) ? <Badge v={outcome(i)!} /> : <span className="meta">–</span>}</td>
                  <td><code>{i.action ?? (i.event === "policy_activated" ? i.policy_hash.slice(7, 19) + "…" : "")}</code></td>
                  <td className="meta">{i.reason}{i.rule ? ` · ${i.rule}` : ""}</td>
                </tr>
              ))}
              {!shown.length && <tr><td colSpan={6} className="meta">no capsules yet</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <section className="col">
        <div className={`card verify ${result ? (result.verified ? "ok" : "bad") : ""}`}>
          <h2>
            Verify offline <span className="sub">the kervix-verify checks, on the ledger as fetched from the vehicle</span>
          </h2>
          <div className="actions">
            <button className="btn approve" disabled={busy || !items.length} onClick={() => void verify()}>{busy ? "verifying…" : "✓ Verify now"}</button>
            <button className="btn" disabled={busy || sel === null} onClick={() => void verify(sel ?? undefined)}
              title="Verifies a copy in which the selected capsule's timestamp is changed by a few milliseconds">
              Edit capsule #{sel ?? "?"} and verify
            </button>
          </div>
          {result && (
            <>
              <div className="verdict">
                <span className={`badge ${result.verified ? "EXECUTED" : "BLOCK"}`}>{result.verified ? "✓ VERIFIED" : "✕ NOT VERIFIED"}</span>
                <span className="meta"> · {result.capsules} capsules · {result.epochs} epoch(s) · {result.elapsed_ms} ms{result.tampered_seq ? ` · capsule #${result.tampered_seq} was edited for this check` : ""}</span>
              </div>
              <ul className="checks">
                {CHECKS.filter(([c]) => c !== "policy" || result.policies.length || result.findings.some((f) => f.check === "policy")).map(([c, what]) => {
                  const bad = result.findings.filter((f) => f.check === c);
                  const extra = c === "replay" ? ` · ${result.replay.match}/${result.replay.match + result.replay.mismatch + result.replay.unknown_policy} decisions${result.replay.policies.length > 1 ? ` under ${result.replay.policies.length} policies` : ""}`
                    : c === "semantics" ? ` · ${result.executed} executed grant(s)` : c === "policy" ? ` · ${result.policies.length} bundle(s)` : "";
                  return (
                    <li key={c} className={bad.length ? "bad" : ""}>
                      <span>{bad.length ? "✘" : "✔"}</span> <b>{c}</b> <span className="meta">{what}{extra}</span>
                      {bad.slice(0, 4).map((f, k) => (
                        <div key={k} className="finding" onClick={() => { const m = /#(\d+)/.exec(f.where); if (m) setSel(Number(m[1]) + (info?.first_seq ?? 1) - 1); }}>
                          {f.where}: {f.message}
                        </div>
                      ))}
                    </li>
                  );
                })}
              </ul>
            </>
          )}
        </div>
        <div className="card detail">
          <h2>
            {selItem ? <>Capsule #{selItem.seq} <span className="sub">{EVENT_LABEL[selItem.event] ?? selItem.event}{selItem.action ? ` · ${selItem.action}` : ""}</span></> : "Select a capsule"}
          </h2>
          {detail && <CapsuleDetail capsule={detail.capsule as Record<string, never>} />}
        </div>
      </section>
    </main>
  );
}

function CapsuleDetail({ capsule }: { capsule: Record<string, never> }) {
  const c = capsule as unknown as {
    capsule_id: string; timestamp: string; action_type: string; chain?: { parent_capsule_id: string; relation: string };
    disposition: { approver: string; decision: string; verdict_class?: string; authority: string; human_disposed: boolean };
    epoch_id: string; effect?: { type: string; status: string; irreversibility_class: string };
  };
  const rows: [string, string][] = [
    ["capsule id", c.capsule_id],
    ["time", c.timestamp],
    ["chain", c.chain ? `${c.chain.relation} ${c.chain.parent_capsule_id.slice(0, 16)}…` : "genesis"],
    ["disposition", `${c.disposition.decision} · approver ${c.disposition.approver}${c.disposition.human_disposed ? " (human)" : ""}${c.disposition.verdict_class ? ` · ${c.disposition.verdict_class}` : ""}`],
    ["policy (authority)", c.disposition.authority],
    ["epoch", c.epoch_id.slice(0, 23) + "…"],
  ];
  if (c.effect) rows.push(["effect", `${c.effect.type} · ${c.effect.status} · ${c.effect.irreversibility_class}`]);
  return (
    <>
      <table className="data kv">
        <tbody>{rows.map(([k, v]) => <tr key={k}><th>{k}</th><td><code>{v}</code></td></tr>)}</tbody>
      </table>
      <pre className="json">{JSON.stringify(capsule, null, 2)}</pre>
    </>
  );
}
