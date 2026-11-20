// Client side of the kxgw wire format (target/kxgw/wire.h): newline-delimited
// JSON over TCP. Each request carries an "id"; the gateway answers with one or
// more lines carrying that id, the last one with "done":true. Lines without an
// id are pushes (escalation list, telemetry, stats).
import { EventEmitter } from "node:events";
import net from "node:net";

export type GwMsg = { kind: string; id?: string; done?: boolean; [k: string]: unknown };
export type GwRequest = { op: string; [k: string]: unknown };
export type Role = "agent" | "hmi" | "observer" | "world";

export const DEFAULT_PORTS: Record<Role, number> = { agent: 7301, hmi: 7302, observer: 7303, world: 7304 };

export class GatewayError extends Error {
  readonly messages: GwMsg[];
  constructor(message: string, messages: GwMsg[] = []) {
    super(message);
    this.messages = messages;
  }
}

let nextId = 1;
function newId(role: string): string {
  return `${role}-${process.pid}-${nextId++}`;
}

/** Split a byte stream into lines and parse each as JSON (malformed lines are reported, not thrown).
 *  Gateway messages must carry a string "kind"; pass requireKind=false to read requests ("op"). */
export function lineReader(onMsg: (m: GwMsg) => void, onBad: (line: string) => void, requireKind = true): (chunk: Buffer) => void {
  let buf = "";
  return (chunk) => {
    buf += chunk.toString("latin1");
    for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      try {
        const m = JSON.parse(line) as GwMsg;
        if (m && typeof m === "object" && !Array.isArray(m) && (!requireKind || typeof m.kind === "string")) onMsg(m);
        else onBad(line);
      } catch {
        onBad(line);
      }
    }
    if (buf.length > 1 << 20) buf = ""; // a gateway never sends this; do not grow without bound
  };
}

/** One request on its own connection: connect, send, collect lines until done, close.
 *  Used for agent proposals: an awaiting proposal blocks its connection until the
 *  driver decides, so proposals must not share one. */
export function oneShot(
  host: string,
  port: number,
  req: GwRequest,
  opts: { timeoutMs?: number; onMsg?: (m: GwMsg) => void } = {},
): Promise<GwMsg[]> {
  const id = (req.id as string | undefined) ?? newId("req");
  const timeoutMs = opts.timeoutMs ?? 120_000;
  return new Promise((resolve, reject) => {
    const msgs: GwMsg[] = [];
    let settled = false;
    const sock = net.connect(port, host);
    const finish = (err?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      if (err) reject(err);
      else resolve(msgs);
    };
    const timer = setTimeout(() => finish(new GatewayError(`timeout after ${timeoutMs} ms`, msgs)), timeoutMs);
    sock.setNoDelay(true);
    sock.on("connect", () => sock.write(JSON.stringify({ ...req, id }) + "\n"));
    sock.on(
      "data",
      lineReader(
        (m) => {
          if (m.id !== id && !(m.kind === "error" && m.id === undefined)) return; // pushes are not ours
          msgs.push(m);
          opts.onMsg?.(m);
          if (m.done) finish(m.kind === "error" ? new GatewayError(String(m.error), msgs) : undefined);
        },
        () => {},
      ),
    );
    sock.on("error", (e: NodeJS.ErrnoException) => finish(new GatewayError(`${host}:${port}: ${e.code ?? e.message}`, msgs)));
    sock.on("close", () => finish(new GatewayError("gateway closed the connection", msgs)));
  });
}

type Pending = { msgs: GwMsg[]; resolve: (m: GwMsg[]) => void; reject: (e: Error) => void; onMsg?: (m: GwMsg) => void; timer: NodeJS.Timeout };

/** A persistent, self-reconnecting connection to one gateway role.
 *  Events: "up" (hello message), "down" (reason), "push" (message without a pending id). */
export class GatewayConnection extends EventEmitter {
  readonly role: Role;
  readonly host: string;
  readonly port: number;
  hello: GwMsg | null = null;
  private sock: net.Socket | null = null;
  private pending = new Map<string, Pending>();
  private closed = false;
  private retryMs: number;
  private readonly onConnectRequest: GwRequest | null;

  constructor(role: Role, host: string, port: number, opts: { retryMs?: number; onConnect?: GwRequest } = {}) {
    super();
    this.role = role;
    this.host = host;
    this.port = port;
    this.retryMs = opts.retryMs ?? 1000;
    this.onConnectRequest = opts.onConnect ?? null;
  }

  get up(): boolean {
    return this.hello !== null;
  }

  start(): this {
    this.connect();
    return this;
  }

  stop(): void {
    this.closed = true;
    this.sock?.destroy();
  }

  request(req: GwRequest, opts: { timeoutMs?: number; onMsg?: (m: GwMsg) => void } = {}): Promise<GwMsg[]> {
    const sock = this.sock;
    if (!sock || !this.up) return Promise.reject(new GatewayError(`${this.role} gateway is down`));
    const id = newId(this.role);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new GatewayError(`${this.role}: timeout`));
      }, opts.timeoutMs ?? 30_000);
      this.pending.set(id, { msgs: [], resolve, reject, onMsg: opts.onMsg, timer });
      sock.write(JSON.stringify({ ...req, id }) + "\n");
    });
  }

  private connect(): void {
    if (this.closed) return;
    const sock = net.connect(this.port, this.host);
    this.sock = sock;
    sock.setNoDelay(true);
    const helloId = newId(this.role);
    sock.on("connect", () => {
      sock.write(JSON.stringify({ op: "hello", id: helloId }) + "\n");
      if (this.onConnectRequest) sock.write(JSON.stringify({ ...this.onConnectRequest, id: newId(this.role) }) + "\n");
    });
    sock.on(
      "data",
      lineReader(
        (m) => {
          if (m.id === helloId) {
            if (m.kind === "hello") {
              this.hello = m;
              this.emit("up", m);
            }
            return;
          }
          const p = m.id !== undefined ? this.pending.get(m.id) : undefined;
          if (!p) {
            this.emit("push", m);
            return;
          }
          p.msgs.push(m);
          p.onMsg?.(m);
          if (m.done) {
            clearTimeout(p.timer);
            this.pending.delete(m.id as string);
            if (m.kind === "error") p.reject(new GatewayError(String(m.error), p.msgs));
            else p.resolve(p.msgs);
          }
        },
        (line) => this.emit("bad", line),
      ),
    );
    sock.on("error", () => {});
    sock.on("close", () => {
      const was = this.up;
      this.hello = null;
      this.sock = null;
      for (const [id, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new GatewayError(`${this.role} gateway connection lost`, p.msgs));
        this.pending.delete(id);
      }
      if (was) this.emit("down", "connection lost");
      if (!this.closed) setTimeout(() => this.connect(), this.retryMs);
    });
  }
}
