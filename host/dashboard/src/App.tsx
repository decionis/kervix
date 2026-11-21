import { lazy, Suspense, useState } from "react";

import { LedgerView } from "./Ledger.tsx";

import { lastDecision } from "./model.ts";
import { Badge, EscalationCard, Feed, LatencyHistogram, TelemetryStrip, Tiles, WorldControls } from "./panels.tsx";
import { useBridge } from "./useBridge.ts";

const CarTwin = lazy(() => import("./Car.tsx").then((m) => ({ default: m.CarTwin })));

const ROLES = ["agent", "hmi", "observer", "world"];

export function App() {
  const { state, send } = useBridge();
  const [view, setView] = useState<"live" | "ledger">("live");
  const offline = state.connected && state.authority.up === false;
  const last = lastDecision(state.feed);
  const showToast = last && Date.now() - last.t < 8000;
  const emulated = Object.values(state.gateways).some((g) => g.hello && !g.hello.fake) && state.target.startsWith("127.");

  return (
    <div className="app">
      <div>
        {state.fake && <div className="fakebar">FAKE TARGET: UI development only. No Kervix, no QNX, nothing is decided or signed.</div>}
        <header className="top">
          <div className="brand">
            KERVIX<small>QNX 8.0 · {emulated ? "QEMU emulation" : state.target || "…"}</small>
          </div>
          <nav className="tabs">
            <button className={view === "live" ? "on" : ""} onClick={() => setView("live")}>Live</button>
            <button className={view === "ledger" ? "on" : ""} onClick={() => setView("ledger")}>
              Ledger{state.ledger ? ` · ${state.ledger.records}` : ""}
            </button>
          </nav>
          <div className="chips">
            <span className="chip">
              <span className="dot" style={{ background: state.connected ? "var(--good)" : "var(--critical)" }} />
              bridge {state.connected ? "connected" : "offline"}
            </span>
            <span className="chip" title="kervixd, from the observer's stats stream">
              <span className="dot" style={{ background: state.authority.up ? "var(--good)" : state.authority.up === false ? "var(--critical)" : "var(--ink-muted)" }} />
              authority {state.authority.up ? "up" : state.authority.up === false ? "DOWN" : "?"}
            </span>
            {ROLES.map((r) => {
              const g = state.gateways[r];
              return (
                <span className="chip" key={r} title={g?.hello ? `pid ${g.hello.pid} · uid ${g.hello.uid} · prio ${g.hello.prio}` : "down"}>
                  <span className="dot" style={{ background: g?.up ? "var(--good)" : "var(--critical)" }} />
                  {r} {g?.hello?.type ? <code>{g.hello.type}</code> : ""}
                </span>
              );
            })}
          </div>
        </header>
      </div>

      {view === "ledger" ? <LedgerView info={state.ledger} /> : <main className="main">
        <section className="col">
          <div className="card twin">
            <Suspense fallback={<div className="overlay">loading 3D…</div>}>
              <CarTwin tel={state.telemetry.tel} offline={offline} verdict={last?.verdict ?? null} pending={state.escalations.length} />
            </Suspense>
            {showToast && last && (
              <div className="toast" aria-live="polite">
                <Badge v={last.verdict} /> <code>{last.action}</code> {last.reason}
              </div>
            )}
            {offline && (
              <div className="overlay offline">
                <div className="banner">
                  <b>AUTHORITY OFFLINE · ACTUATION LOCKED</b>
                  kervixd is not answering. Every action is refused until it is back (fail closed).
                </div>
              </div>
            )}
          </div>
          <TelemetryStrip tel={state.telemetry.tel} ageUs={state.telemetry.ageUs} plausible={state.telemetry.plausible} />
          <WorldControls tel={state.telemetry.tel} onSim={(cmd) => void send("sim", { cmd })} />
        </section>
        <section className="col">
          <EscalationCard
            items={state.escalations}
            receivedAt={state.escAt}
            onResolve={async (id, approve) => {
              await send("resolve", { escalation_id: id, approve, approver: "hmi:dashboard-driver" });
            }}
          />
          <div className="card">
            <h2>
              Authority <span className="sub">{state.stats?.policy ? `policy ${state.stats.policy}` : ""}{state.stats?.uptimeS != null ? ` · up ${state.stats.uptimeS} s` : ""}</span>
            </h2>
            <Tiles s={state.stats} />
          </div>
          <LatencyHistogram s={state.stats} emulated={emulated} />
          <Feed feed={state.feed} emulated={emulated} />
        </section>
      </main>}
    </div>
  );
}
