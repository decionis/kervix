import { useEffect, useState } from "react";

import { driverText } from "./driverText.ts";
import { GEAR, denseHistogram, fmtParams, type Escalation, type FeedEvent, type GwMsg, type Stats, type Tel } from "./model.ts";

// ---------------------------------------------------------------- verdicts

const ICON: Record<string, string> = { ALLOW: "✓", EXECUTED: "✓", ESCALATE: "!", BLOCK: "✕", REFUSED: "✕", ERROR: "✕" };
export function Badge({ v }: { v: string }) {
  // status color + icon + label: never color alone
  return (
    <span className={`badge ${v}`}>
      <span aria-hidden>{ICON[v] ?? "•"}</span>
      {v}
    </span>
  );
}

// ---------------------------------------------------------------- telemetry

export function TelemetryStrip({ tel, ageUs, plausible }: { tel: Tel | null; ageUs: number; plausible: boolean }) {
  const t = tel ?? {};
  const cell = (k: string, v: string, unit = "") => (
    <div>
      <div className="k">{k}</div>
      <div className="v">
        {tel ? v : "–"}
        {tel && unit && <small>{unit}</small>}
      </div>
    </div>
  );
  return (
    <div className="card">
      <h2>
        Vehicle state <span className="sub">as reported by vsimd on QNX · sample age {(ageUs / 1000).toFixed(1)} ms{plausible ? "" : " · IMPLAUSIBLE"}</span>
      </h2>
      <div className="tel">
        {cell("Speed", ((t.speed_dkph ?? 0) / 10).toFixed(0), "km/h")}
        {cell("Gear", GEAR[t.gear ?? 0] ?? "?")}
        {cell("Park brake", t.park_brake ? "on" : "off")}
        {cell("Battery", ((t.soc_dpct ?? 0) / 10).toFixed(1), t.charging ? "% ⚡" : "%")}
        {cell("Cabin", ((t.hvac_setpoint_dc ?? 0) / 10).toFixed(1), "°C")}
        {cell("Driver", t.driver_present ? "present" : "absent")}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- escalation

export function EscalationCard({ items, receivedAt, onResolve }: { items: Escalation[]; receivedAt: number; onResolve: (id: number, approve: boolean) => Promise<void> }) {
  const [now, setNow] = useState(Date.now());
  const [busy, setBusy] = useState<number | null>(null);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 200);
    return () => clearInterval(t);
  }, []);
  if (items.length === 0) return null;
  const e = items[0];
  const left = Math.max(0, e.remaining_ms - (now - receivedAt));
  const total = 30000;
  const act = async (approve: boolean) => {
    setBusy(e.escalation_id);
    await onResolve(e.escalation_id, approve);
    setBusy(null);
  };
  const t = driverText(e.intent, e.reason, e.reason_text);
  const secs = Math.ceil(left / 1000);
  return (
    <div className="card esc" role="alertdialog" aria-label="Your approval is needed">
      <h2>
        <span className="badge ESCALATE"><span aria-hidden>!</span>Your approval is needed</span>
        {items.length > 1 && <span className="sub"> · {items.length - 1} more waiting</span>}
      </h2>
      <div className="what">{t.action}</div>
      <div className="why">
        {t.why} Requested by {t.requester}.{t.consequence ? ` ${t.consequence}` : ""}
      </div>
      {t.reference && <div className="ref">Update {t.reference}</div>}
      <div className="meter" title={`${secs} s left`}>
        <div style={{ width: `${Math.min(100, (left / total) * 100)}%` }} />
      </div>
      <div className="actions">
        <button className="btn approve" disabled={busy !== null} onClick={() => act(true)}>
          ✓ Approve
        </button>
        <button className="btn deny" disabled={busy !== null} onClick={() => act(false)}>
          ✕ Deny
        </button>
        <span className="countdown">{secs} s left · if you don't answer, it won't happen</span>
      </div>
      <div className="tech">
        #{e.escalation_id} · {e.intent.action} · rule {e.rule} · {e.intent.actor} · re-checked on live vehicle state before anything runs
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- stats

export function Tiles({ s }: { s: Stats | null }) {
  const tile = (label: string, value: number | string, v?: string) => (
    <div className="tile">
      <div className="label">
        {v && <span className="dot" style={{ background: v === "ALLOW" ? "var(--good)" : v === "ESCALATE" ? "var(--warning)" : "var(--critical)" }} />}
        {label}
      </div>
      <div className="value">{typeof value === "number" ? value.toLocaleString() : value}</div>
    </div>
  );
  return (
    <div className="tiles">
      {tile("Proposals", s?.proposals ?? 0)}
      {tile("Allowed", s?.allow ?? 0, "ALLOW")}
      {tile("Escalated", s?.escalate ?? 0, "ESCALATE")}
      {tile("Blocked", s?.block ?? 0, "BLOCK")}
    </div>
  );
}

const fmtUs = (us: number) => (us >= 1000 ? `${us / 1000} ms` : `${us} µs`);

/** PROPOSE latency inside kervixd, log2 buckets. Single series: no legend; the title names it. */
export function LatencyHistogram({ s, emulated }: { s: Stats | null; emulated: boolean }) {
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  const h = denseHistogram(s?.hist ?? []);
  const W = 420, H = 150, padL = 34, padB = 30, padT = 8;
  const max = Math.max(1, ...h.map((b) => b.n));
  const nice = Math.pow(10, Math.ceil(Math.log10(max)));
  const top = [1, 2, 5, 10].map((f) => (f * nice) / 10).find((v) => v >= max) ?? nice;
  const slot = h.length ? (W - padL) / h.length : 0;
  const bw = Math.min(24, Math.max(4, slot - 2));
  const y = (n: number) => padT + (H - padT - padB) * (1 - n / top);
  return (
    <div className="card">
      <h2>
        PROPOSE latency in kervixd{" "}
        <span className="sub">
          {s?.p50us ? `p50 < ${fmtUs(s.p50us)} · p99 < ${fmtUs(s.p99us ?? 0)}` : "no proposals yet"}
          {emulated ? " · QEMU/TCG: emulated, not representative" : ""}
        </span>
        <button className="toggle" style={{ float: "right" }} onClick={() => setTable(!table)}>
          {table ? "chart" : "table"}
        </button>
      </h2>
      {table ? (
        <table className="data">
          <thead>
            <tr><th>bucket</th><th>proposals</th></tr>
          </thead>
          <tbody>
            {h.map((b) => (
              <tr key={b.hi}><td>{`${fmtUs(b.lo)} – ${fmtUs(b.hi)}`}</td><td>{b.n.toLocaleString()}</td></tr>
            ))}
          </tbody>
        </table>
      ) : (
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="PROPOSE latency histogram" onMouseLeave={() => setHover(null)}>
          {[0, top / 2, top].map((v) => (
            <g key={v}>
              <line x1={padL} x2={W} y1={y(v)} y2={y(v)} stroke={v === 0 ? "var(--axis)" : "var(--grid)"} strokeWidth={1} />
              <text x={padL - 6} y={y(v) + 4} fontSize={10} fill="var(--ink-muted)" textAnchor="end" style={{ fontVariantNumeric: "tabular-nums" }}>
                {v >= 10000 ? `${v / 1000}K` : v.toLocaleString()}
              </text>
            </g>
          ))}
          {h.map((b, i) => {
            const x = padL + i * slot + (slot - bw) / 2;
            const yt = y(b.n), yb = y(0), r = Math.min(4, (yb - yt) / 2);
            return (
              <g key={b.hi} onMouseEnter={() => setHover(i)}>
                <rect x={padL + i * slot} y={padT} width={slot} height={H - padT - padB} fill="transparent" />
                {b.n > 0 && (
                  <path
                    d={`M${x},${yb} L${x},${yt + r} Q${x},${yt} ${x + r},${yt} L${x + bw - r},${yt} Q${x + bw},${yt} ${x + bw},${yt + r} L${x + bw},${yb} Z`}
                    fill="var(--series-1)"
                    opacity={hover === null || hover === i ? 1 : 0.45}
                  />
                )}
                {(i % 2 === 0 || h.length < 8) && (
                  <text x={padL + i * slot + slot / 2} y={H - padB + 14} fontSize={10} fill="var(--ink-muted)" textAnchor="middle">
                    {fmtUs(b.hi)}
                  </text>
                )}
              </g>
            );
          })}
          <text x={W} y={H - 2} fontSize={10} fill="var(--ink-muted)" textAnchor="end">upper bound of each log2 bucket</text>
          {hover !== null && h[hover] && (
            <g pointerEvents="none">
              <rect x={Math.min(W - 150, padL + hover * slot)} y={padT} width={150} height={34} rx={6} fill="var(--surface-2)" stroke="var(--ring)" />
              <text x={Math.min(W - 150, padL + hover * slot) + 8} y={padT + 14} fontSize={11} fill="var(--ink-1)">
                {fmtUs(h[hover].lo)} – {fmtUs(h[hover].hi)}
              </text>
              <text x={Math.min(W - 150, padL + hover * slot) + 8} y={padT + 28} fontSize={11} fill="var(--ink-2)">
                {h[hover].n.toLocaleString()} proposals
              </text>
            </g>
          )}
        </svg>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- feed

function line(e: FeedEvent): React.ReactNode {
  const m = e.msg as GwMsg & Record<string, unknown>;
  const intent = m.intent as { action: string; actor: string; params: Record<string, unknown> } | undefined;
  switch (m.kind) {
    case "note": {
      const role = String(m.role);
      if (role === "user") return <span className="say">🧑 Driver: “{String(m.text)}”</span>;
      if (role === "assistant") return <span className="say">🤖 Agent: “{String(m.text)}”</span>;
      if (role === "thinking") return <span className="think">reasoning summary: {String(m.text)}</span>;
      if (role === "tool_call") return <span className="meta">agent proposes <code>{String(m.tool)}</code> <code>{fmtParams(m.input as Record<string, unknown>)}</code></span>;
      if (role === "mismatch") return <span><Badge v="ERROR" /> scripted transcript no longer matches the live verdict</span>;
      if (role === "refusal" || role === "fallback") return <span className="meta">model {role}: {String(m.text ?? m.category ?? "")}</span>;
      return null; // tool_result: the Kervix decision lines carry it
    }
    case "decision":
    case "resolution":
      return (
        <span>
          <Badge v={String(m.verdict)} /> <code>{intent?.action}</code> {String(m.reason)}
          <span className="meta">
            {" "}· {m.kind === "resolution" ? (m.reason === "ESCALATION_TIMEOUT" ? "nobody answered in time" : "after the driver's decision") : `rule ${m.rule || "default"}`}
            {Number(m.eval_ns) > 0 ? ` · ${(Number(m.eval_ns) / 1000).toFixed(0)} µs in kervixd` : ""}
          </span>
        </span>
      );
    case "execution":
      return (
        <span>
          <Badge v={String(m.result)} /> actuator {m.result === "EXECUTED" ? "applied the granted command" : `refused: ${String(m.reason)}`}
        </span>
      );
    case "resolved":
      return <span className="meta">driver {m.approve ? "approved" : "denied"} escalation #{String(m.escalation_id)} ({String(m.approver)})</span>;
    case "sim":
      return <span className="meta">world: {(m.reply as string[] | undefined)?.join(" ")}</span>;
    case "error":
      return <span><Badge v="ERROR" /> {String(m.error)}</span>;
    default:
      return null;
  }
}

export function Feed({ feed }: { feed: FeedEvent[] }) {
  const rows = feed.map((e) => [e, line(e)] as const).filter(([, n]) => n !== null).slice(-80).reverse();
  return (
    <div className="card feed">
      <h2>
        Decisions &amp; agent <span className="sub">newest first · every verdict is decided on QNX and signed into the ledger</span>
      </h2>
      <ol>
        {rows.map(([e, node]) => (
          <li key={e.seq}>
            <time>{new Date(e.t).toLocaleTimeString([], { hour12: false })}</time>
            <div>{node}</div>
          </li>
        ))}
        {rows.length === 0 && <li><time /> <div className="meta">waiting for the agent…</div></li>}
      </ol>
    </div>
  );
}

// ---------------------------------------------------------------- world

const SCENARIOS = ["park", "charging", "city", "highway"];
export function WorldControls({ tel, onSim }: { tel: Tel | null; onSim: (cmd: string) => void }) {
  return (
    <div className="card">
      <h2>
        World <span className="sub">the simulated road and driver (demo control; not a vehicle interface)</span>
      </h2>
      <div className="world">
        {SCENARIOS.map((s) => (
          <button key={s} className="btn" onClick={() => onSim(`scenario ${s}`)}>{s}</button>
        ))}
        <button className="btn" onClick={() => onSim(`driver ${tel?.driver_present ? 0 : 1}`)}>
          driver {tel?.driver_present ? "leaves" : "returns"}
        </button>
      </div>
    </div>
  );
}
