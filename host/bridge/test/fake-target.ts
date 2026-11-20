// A FAKE kxgw target: speaks the same wire format as the four QNX gateways so
// the bridge, agent and dashboard can be tested in CI and developed without
// QEMU. It is NOT Kervix: its "policy" is a few hard-coded lines, it signs
// nothing and records nothing. Every hello says "fake": true and the dashboard
// shows a FAKE TARGET banner. Never use it for a demo or a measurement.
//
//   node host/bridge/test/fake-target.ts     (listens on 127.0.0.1:7301-7304)
import { randomBytes, randomUUID } from "node:crypto";
import net from "node:net";
import { fileURLToPath } from "node:url";

import { lineReader, type GwMsg, type Role } from "../src/gateway.ts";

type Tel = Record<string, number>;
type Esc = { escalation_id: number; reason: string; reason_text: string; rule: string; remaining_ms: number; proposer_pid: number; intent: Record<string, unknown>; waiter?: (approve: boolean) => void };

export class FakeTarget {
  servers: net.Server[] = [];
  ports: Record<Role, number> = { agent: 0, hmi: 0, observer: 0, world: 0 };
  tel: Tel = { speed_dkph: 0, gear: 0, park_brake: 1, soc_dpct: 800, charging: 0, driver_present: 1, service_mode: 0, doors_locked_mask: 15, hvac_setpoint_dc: 210, window_fl_pct: 0, window_fr_pct: 0, window_rl_pct: 0, window_rr_pct: 0, hazard_on: 0, acc_target_kph: 0, charge_limit_pct: 80, immobilizer_on: 0, location_shared: 0, ota_state: 0 };
  seq = 0;
  /** simulate kervixd being down: stats fail the way the real observer gateway reports it */
  authorityDown = false;
  private grants = new Map<string, { spent: boolean; action: string }>();
  private escs: Esc[] = [];
  private nextEsc = 1;
  private hmiSocks = new Set<net.Socket>();
  private timers: NodeJS.Timeout[] = [];

  async start(ports: Partial<Record<Role, number>> = {}, host = "127.0.0.1"): Promise<this> {
    for (const role of ["agent", "hmi", "observer", "world"] as Role[]) {
      const srv = net.createServer((s) => this.client(role, s));
      await new Promise<void>((resolve) => srv.listen(ports[role] ?? 0, host, resolve));
      this.ports[role] = (srv.address() as net.AddressInfo).port;
      this.servers.push(srv);
    }
    return this;
  }

  async stop(): Promise<void> {
    for (const t of this.timers) clearInterval(t);
    for (const s of this.hmiSocks) s.destroy();
    await Promise.all(this.servers.map((s) => new Promise((r) => { s.close(r); (s as unknown as { closeAllConnections?: () => void }).closeAllConnections?.(); })));
  }

  private send(s: net.Socket, m: GwMsg): void {
    if (!s.destroyed) s.write(JSON.stringify(m) + "\n");
  }

  private telemetry(): Record<string, unknown> {
    return { available: true, age_us: 1200, plausible: true, telemetry: { seq: ++this.seq, mono_ns: Date.now() * 1e6, ...this.tel } };
  }

  private pushEscalations(): void {
    const items = this.escs.map(({ waiter: _w, ...e }) => e);
    for (const s of this.hmiSocks) this.send(s, { kind: "escalations", available: true, items, done: true });
  }

  private decision(verdict: string, reason: string, rule: string, intent: Record<string, unknown>, extra: Record<string, unknown> = {}): Record<string, unknown> {
    return { verdict, reason, reason_text: `(fake) ${reason}`, gate: "RULE", rule, intent_hash: "sha256:" + "0".repeat(64), policy_hash: "sha256:" + "f".repeat(64), telemetry_seq: this.seq, eval_ns: 1000, intent, rtt_us: 50, ...extra };
  }

  private allow(intent: Record<string, unknown>, rule: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    const grant_id = randomBytes(16).toString("hex");
    this.grants.set(grant_id, { spent: false, action: String(intent.action) });
    return this.decision("ALLOW", extra.reason ? String(extra.reason) : "OK", rule, intent, { grant_id, grant_ttl_ms: 500, ...extra });
  }

  private execute(grantId: string): { result: string; reason: string } {
    const g = this.grants.get(grantId);
    if (!g) return { result: "REFUSED", reason: "GRANT_UNKNOWN" };
    if (g.spent) return { result: "REFUSED", reason: "GRANT_SPENT" };
    g.spent = true;
    if (g.action === "body.door.unlock") this.tel.doors_locked_mask = 0;
    if (g.action === "light.hazard.set") this.tel.hazard_on = 1;
    if (g.action === "ota.ecu.flash") this.tel.ota_state = 1;
    return { result: "EXECUTED", reason: "OK" };
  }

  private async propose(s: net.Socket, r: Record<string, unknown>): Promise<void> {
    const id = r.id as string;
    const intent = { action: r.action, actor: r.actor ?? "agent:remote", intent_id: r.intent_id ?? randomUUID(), params: r.params ?? {} };
    const moving = this.tel.speed_dkph > 0;
    let d: Record<string, unknown>;
    if (String(r.action).startsWith("ota.")) {
      d = moving ? this.decision("BLOCK", "R156_NOT_SAFE_STATE", "ota-block-moving", intent) : this.decision("ESCALATE", "DRIVER_CONSENT", "ota-escalate-parked", intent, { escalation_id: this.nextEsc });
    } else if (r.action === "cabin.climate.set") {
      d = this.allow(intent, "climate-any");
    } else {
      d = moving ? this.decision("BLOCK", "NOT_PARKED", "default", intent) : this.allow(intent, "parked");
    }
    const awaiting = d.verdict === "ESCALATE" && r.await === true;
    let executing = d.verdict === "ALLOW" && r.exec === true;
    this.send(s, { kind: "decision", id, ...d, done: !(awaiting || executing) } as GwMsg);
    if (d.verdict === "ESCALATE") {
      const esc: Esc = { escalation_id: this.nextEsc++, reason: "DRIVER_CONSENT", reason_text: "(fake) driver consent", rule: String(d.rule), remaining_ms: 30000, proposer_pid: 1, intent };
      this.escs.push(esc);
      this.pushEscalations();
      if (!awaiting) return;
      const approve = await new Promise<boolean>((resolve) => (esc.waiter = resolve));
      d = approve ? this.allow(intent, String(d.rule), { reason: "HUMAN_APPROVED", escalation_id: esc.escalation_id }) : this.decision("BLOCK", "HUMAN_DENIED", String(d.rule), intent, { escalation_id: esc.escalation_id });
      executing = d.verdict === "ALLOW" && r.exec === true;
      this.send(s, { kind: "resolution", id, ...d, done: !executing } as GwMsg);
    }
    if (executing) this.send(s, { kind: "execution", id, ...this.execute(String(d.grant_id)), grant_id: d.grant_id, done: true });
  }

  private client(role: Role, s: net.Socket): void {
    s.on("error", () => {});
    if (role === "hmi") {
      this.hmiSocks.add(s);
      s.on("close", () => this.hmiSocks.delete(s));
      setImmediate(() => this.pushEscalations());
    }
    let telTimer: NodeJS.Timeout | null = null;
    s.on("close", () => telTimer && clearInterval(telTimer));
    s.on(
      "data",
      lineReader(
        (m) => void this.handle(role, s, m as unknown as Record<string, unknown>, (hz) => {
          if (telTimer) clearInterval(telTimer);
          let k = 0;
          telTimer = setInterval(() => {
            this.send(s, { kind: "telemetry", t_ms: Date.now(), ...this.telemetry(), done: true });
            if (k++ % 5 === 0) {
              if (this.authorityDown) this.send(s, { kind: "error", error: "authority unavailable (is kervixd running?)", done: true });
              else this.send(s, { kind: "stats", text: ["FAKE TARGET (no Kervix)"], done: true });
            }
          }, 1000 / hz);
          this.timers.push(telTimer);
        }),
        () => this.send(s, { kind: "error", error: "expected a JSON object", done: true }),
        false,
      ),
    );
  }

  private async handle(role: Role, s: net.Socket, r: Record<string, unknown>, subscribe: (hz: number) => void): Promise<void> {
    const id = r.id as string | undefined;
    const ops: Record<Role, string[]> = { agent: ["hello", "propose", "execute", "state", "stats"], hmi: ["hello", "escalations", "resolve", "state", "stats"], observer: ["hello", "subscribe", "state", "stats"], world: ["hello", "sim", "state"] };
    if (!ops[role].includes(String(r.op))) return this.send(s, { kind: "error", id, error: `op '${r.op}' is not available on the ${role} gateway`, done: true });
    switch (r.op) {
      case "hello":
        return this.send(s, { kind: "hello", id, role, pid: process.pid, uid: 0, type: "fake", prio: 0, abi: 1, fake: true, ops: ops[role], done: true });
      case "state":
        return this.send(s, { kind: "state", id, ...this.telemetry(), done: true });
      case "stats":
        if (this.authorityDown) return this.send(s, { kind: "error", id, error: "authority unavailable (is kervixd running?)", done: true });
        return this.send(s, { kind: "stats", id, text: ["FAKE TARGET (no Kervix)"], done: true });
      case "subscribe":
        subscribe(Math.max(1, Math.min(50, Number(r.hz ?? 10))));
        return this.send(s, { kind: "subscribed", id, hz: r.hz, done: true });
      case "propose":
        return this.propose(s, r);
      case "execute":
        return this.send(s, { kind: "execution", id, ...this.execute(String(r.grant_id)), grant_id: r.grant_id, done: true });
      case "escalations":
        return this.send(s, { kind: "escalations", id, available: true, items: this.escs.map(({ waiter: _w, ...e }) => e), done: true });
      case "resolve": {
        const i = this.escs.findIndex((e) => e.escalation_id === Number(r.escalation_id));
        if (i < 0) return this.send(s, { kind: "error", id, error: "no such escalation", done: true });
        const [e] = this.escs.splice(i, 1);
        e.waiter?.(r.approve === true);
        this.pushEscalations();
        return this.send(s, { kind: "resolved", id, escalation_id: e.escalation_id, approve: r.approve === true, approver: r.approver ?? "hmi:driver", done: true });
      }
      case "sim": {
        const cmd = String(r.cmd);
        if (cmd === "scenario highway") Object.assign(this.tel, { speed_dkph: 1100, gear: 3, park_brake: 0, charging: 0 });
        else if (cmd === "scenario city") Object.assign(this.tel, { speed_dkph: 300, gear: 3, park_brake: 0, charging: 0 });
        else if (cmd === "scenario park") Object.assign(this.tel, { speed_dkph: 0, gear: 0, park_brake: 1, charging: 0 });
        else if (cmd === "scenario charging") Object.assign(this.tel, { speed_dkph: 0, gear: 0, park_brake: 1, charging: 1 });
        return this.send(s, { kind: "sim", id, ok: true, reply: [`ok ${cmd} (fake)`], done: true });
      }
    }
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const t = await new FakeTarget().start({ agent: 7301, hmi: 7302, observer: 7303, world: 7304 });
  console.log(`FAKE kxgw target (NOT Kervix; UI development only) on 127.0.0.1:${t.ports.agent}-${t.ports.world}`);
}
