// host/bridge: joins the four kxgw roles on the QNX target to the host domain.
//   target  agent :7301  -> one short-lived connection per proposal (awaits block)
//           hmi   :7302  -> persistent; escalation pushes
//           obs   :7303  -> persistent; telemetry + stats stream
//           world :7304  -> persistent; scenario control (the simulated road)
//   host    WebSocket /ws   fan-out to dashboards (snapshot on connect, then events)
//           REST /api/*     for the agent (host/agent) and scripts
// The bridge holds no authority either: every verdict comes from kervixd on the
// target. It only routes, records a feed, and shows what happened.
import { EventEmitter } from "node:events";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { WebSocketServer, type WebSocket } from "ws";

import { DEFAULT_PORTS, GatewayConnection, GatewayError, oneShot, type GwMsg, type GwRequest, type Role } from "./gateway.ts";

export type BridgeOptions = {
  target: string;
  ports?: Partial<Record<Role, number>>;
  listen?: { host: string; port: number };
  telemetryHz?: number;
  staticDir?: string;
  log?: (line: string) => void;
};

export type FeedEvent = { seq: number; t: number; source: string; msg: GwMsg };

export type ProposeInput = {
  action: string;
  params?: Record<string, string | number | boolean>;
  actor?: string;
  intent_id?: string;
  expires_at_ms?: number;
  exec?: boolean;
  await?: boolean;
};

const FEED_MAX = 300;
const BODY_MAX = 64 * 1024;

export class Bridge extends EventEmitter {
  readonly opts: Required<Omit<BridgeOptions, "staticDir" | "ports">> & { staticDir?: string; ports: Record<Role, number> };
  readonly gw: Record<Role, GatewayConnection>;
  telemetry: GwMsg | null = null;
  stats: string[] = [];
  escalations: unknown[] = [];
  feed: FeedEvent[] = [];
  /** kervixd reachable? Derived from the observer's stats stream (1 Hz): stats = up, "authority unavailable" = down. */
  authority: { up: boolean | null; since: number } = { up: null, since: Date.now() };
  private seq = 0;
  private server: http.Server | null = null;
  private wss: WebSocketServer | null = null;

  constructor(opts: BridgeOptions) {
    super();
    this.opts = {
      target: opts.target,
      ports: { ...DEFAULT_PORTS, ...(opts.ports ?? {}) },
      listen: opts.listen ?? { host: "127.0.0.1", port: 8787 },
      telemetryHz: opts.telemetryHz ?? 10,
      staticDir: opts.staticDir,
      log: opts.log ?? ((l) => console.log(l)),
    };
    const p = this.opts.ports;
    const t = this.opts.target;
    this.gw = {
      agent: new GatewayConnection("agent", t, p.agent),
      hmi: new GatewayConnection("hmi", t, p.hmi),
      observer: new GatewayConnection("observer", t, p.observer, { onConnect: { op: "subscribe", hz: this.opts.telemetryHz } }),
      world: new GatewayConnection("world", t, p.world),
    };
    for (const role of Object.keys(this.gw) as Role[]) {
      const c = this.gw[role];
      c.on("up", (hello: GwMsg) => {
        this.opts.log(`bridge: ${role} gateway up (${hello.type || "untyped"}, uid ${hello.uid}, prio ${hello.prio})`);
        this.broadcast({ type: "gateway", role, up: true, hello });
      });
      c.on("down", () => {
        this.opts.log(`bridge: ${role} gateway DOWN`);
        this.broadcast({ type: "gateway", role, up: false });
      });
      c.on("push", (m: GwMsg) => this.onPush(role, m));
    }
  }

  // ------------------------------------------------------------------ target

  private onPush(role: Role, m: GwMsg): void {
    if (m.kind === "telemetry") {
      this.telemetry = m;
      this.broadcast({ type: "telemetry", ...m });
    } else if (m.kind === "stats" && Array.isArray(m.text)) {
      this.stats = m.text as string[];
      this.setAuthority(true);
      this.broadcast({ type: "stats", text: this.stats });
    } else if (m.kind === "error" && role === "observer" && /authority unavailable/.test(String(m.error))) {
      this.setAuthority(false);
    } else if (m.kind === "escalations" && role === "hmi") {
      this.escalations = Array.isArray(m.items) ? m.items : [];
      this.broadcast({ type: "escalations", items: this.escalations, available: m.available });
    }
  }

  private setAuthority(up: boolean): void {
    if (this.authority.up === up) return;
    this.authority = { up, since: Date.now() };
    this.opts.log(`bridge: authority ${up ? "UP" : "DOWN (actuation locked)"}`);
    this.broadcast({ type: "authority", ...this.authority });
  }

  private record(source: string, msg: GwMsg): void {
    const ev: FeedEvent = { seq: ++this.seq, t: Date.now(), source, msg };
    this.feed.push(ev);
    if (this.feed.length > FEED_MAX) this.feed.shift();
    this.broadcast({ type: "feed", event: ev });
    this.emit("feed", ev);
  }

  /** PROPOSE (optionally await the driver and execute). Every line is recorded in the feed. */
  async propose(input: ProposeInput, source = "agent"): Promise<GwMsg[]> {
    const req: GwRequest = { op: "propose", action: input.action, params: input.params ?? {} };
    if (input.actor) req.actor = input.actor;
    if (input.intent_id) req.intent_id = input.intent_id;
    if (input.expires_at_ms) req.expires_at_ms = input.expires_at_ms;
    if (input.exec) req.exec = true;
    if (input.await) req.await = true;
    try {
      return await oneShot(this.opts.target, this.opts.ports.agent, req, { onMsg: (m) => this.record(source, m) });
    } catch (e) {
      if (e instanceof GatewayError && e.messages.length) return e.messages; // the error line is already in the feed
      const msg: GwMsg = { kind: "error", error: (e as Error).message, done: true };
      this.record(source, msg);
      return [msg];
    }
  }

  async execute(grantId: string, source = "agent"): Promise<GwMsg[]> {
    return this.requestRecorded("agent", { op: "execute", grant_id: grantId }, source);
  }

  async resolve(escalationId: number, approve: boolean, approver = "hmi:dashboard", source = "hmi"): Promise<GwMsg[]> {
    return this.requestRecorded("hmi", { op: "resolve", escalation_id: escalationId, approve, approver }, source);
  }

  async sim(cmd: string, source = "world"): Promise<GwMsg[]> {
    return this.requestRecorded("world", { op: "sim", cmd }, source);
  }

  async state(): Promise<GwMsg> {
    const role: Role = this.gw.agent.up ? "agent" : "observer";
    const msgs = await this.gw[role].request({ op: "state" });
    return msgs[msgs.length - 1];
  }

  private async requestRecorded(role: Role, req: GwRequest, source: string): Promise<GwMsg[]> {
    try {
      return await this.gw[role].request(req, { onMsg: (m) => this.record(source, m) });
    } catch (e) {
      if (e instanceof GatewayError && e.messages.length) return e.messages;
      const msg: GwMsg = { kind: "error", error: (e as Error).message, done: true };
      this.record(source, msg);
      return [msg];
    }
  }

  /** Free-form host-side events for the dashboard (agent narration, reasoning summaries). */
  note(source: string, payload: Record<string, unknown>): void {
    this.record(source, { kind: "note", done: true, ...payload });
  }

  snapshot(): Record<string, unknown> {
    const gateways: Record<string, unknown> = {};
    for (const role of Object.keys(this.gw) as Role[]) gateways[role] = { up: this.gw[role].up, hello: this.gw[role].hello };
    return { type: "snapshot", target: this.opts.target, gateways, authority: this.authority, telemetry: this.telemetry, stats: this.stats, escalations: this.escalations, feed: this.feed };
  }

  // -------------------------------------------------------------------- host

  private broadcast(obj: Record<string, unknown>): void {
    if (!this.wss) return;
    const s = JSON.stringify(obj);
    for (const ws of this.wss.clients) if (ws.readyState === 1) ws.send(s);
  }

  async start(): Promise<{ port: number }> {
    for (const c of Object.values(this.gw)) c.start();
    this.server = http.createServer((req, res) => void this.http(req, res));
    this.wss = new WebSocketServer({ server: this.server, path: "/ws", maxPayload: BODY_MAX });
    this.wss.on("connection", (ws) => this.onWs(ws));
    await new Promise<void>((resolve) => this.server!.listen(this.opts.listen.port, this.opts.listen.host, resolve));
    const addr = this.server.address();
    const port = typeof addr === "object" && addr ? addr.port : this.opts.listen.port;
    this.opts.log(`bridge: target ${this.opts.target} -> http://${this.opts.listen.host}:${port} (ws /ws, api /api)`);
    return { port };
  }

  async stop(): Promise<void> {
    for (const c of Object.values(this.gw)) c.stop();
    for (const ws of this.wss?.clients ?? []) ws.terminate();
    this.wss?.close();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }

  private onWs(ws: WebSocket): void {
    ws.send(JSON.stringify(this.snapshot()));
    ws.on("message", async (data) => {
      let m: Record<string, unknown>;
      try {
        m = JSON.parse(String(data));
      } catch {
        return;
      }
      const ref = m.ref;
      const reply = (r: Record<string, unknown>) => ws.readyState === 1 && ws.send(JSON.stringify({ type: "reply", ref, ...r }));
      try {
        let messages: GwMsg[];
        if (m.type === "resolve") messages = await this.resolve(Number(m.escalation_id), m.approve === true, String(m.approver ?? "hmi:dashboard"), "dashboard");
        else if (m.type === "sim") messages = await this.sim(String(m.cmd), "dashboard");
        else if (m.type === "propose") messages = await this.propose(m as unknown as ProposeInput, "dashboard");
        else if (m.type === "execute") messages = await this.execute(String(m.grant_id), "dashboard");
        else return reply({ ok: false, error: "unknown message type" });
        const last = messages[messages.length - 1];
        reply({ ok: last?.kind !== "error", messages });
      } catch (e) {
        reply({ ok: false, error: (e as Error).message });
      }
    });
  }

  private async http(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://bridge");
    const send = (code: number, obj: unknown) => {
      res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify(obj));
    };
    try {
      if (url.pathname.startsWith("/api/")) {
        const body = req.method === "POST" ? await readBody(req) : {};
        const route = `${req.method} ${url.pathname}`;
        switch (route) {
          case "GET /api/health":
            return send(200, this.snapshot().gateways);
          case "GET /api/snapshot":
            return send(200, this.snapshot());
          case "GET /api/state":
            return send(200, await this.state());
          case "GET /api/feed":
            return send(200, this.feed.filter((e) => e.seq > Number(url.searchParams.get("after") ?? 0)));
          case "GET /api/escalations":
            return send(200, this.escalations);
          case "POST /api/propose":
            if (typeof body.action !== "string") return send(400, { error: "action required" });
            return send(200, { messages: await this.propose(body as ProposeInput, String(body.source ?? "agent")) });
          case "POST /api/execute":
            return send(200, { messages: await this.execute(String(body.grant_id), String(body.source ?? "agent")) });
          case "POST /api/resolve":
            return send(200, { messages: await this.resolve(Number(body.escalation_id), body.approve === true, String(body.approver ?? "hmi:api")) });
          case "POST /api/sim":
            return send(200, { messages: await this.sim(String(body.cmd)) });
          case "POST /api/note":
            this.note(String(body.source ?? "agent"), body);
            return send(200, { ok: true });
          default:
            return send(404, { error: "no such endpoint" });
        }
      }
      if (this.opts.staticDir && req.method === "GET") return serveStatic(this.opts.staticDir, url.pathname, res);
      send(404, { error: "not found" });
    } catch (e) {
      send(e instanceof BadRequest ? 400 : 502, { error: (e as Error).message });
    }
  }
}

class BadRequest extends Error {}

function readBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > BODY_MAX) {
        reject(new BadRequest("body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      try {
        const v = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
        if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error();
        resolve(v);
      } catch {
        reject(new BadRequest("body must be a JSON object"));
      }
    });
  });
}

const MIME: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".json": "application/json", ".wasm": "application/wasm", ".png": "image/png" };

function serveStatic(root: string, pathname: string, res: http.ServerResponse): void {
  const base = path.resolve(root);
  let file = path.resolve(base, "." + decodeURIComponent(pathname));
  if (!file.startsWith(base + path.sep) && file !== base) {
    res.writeHead(403).end();
    return;
  }
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(base, "index.html"); // SPA fallback
  if (!fs.existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": MIME[path.extname(file)] ?? "application/octet-stream" });
  fs.createReadStream(file).pipe(res);
}
