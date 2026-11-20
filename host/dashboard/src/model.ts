// Dashboard state: a pure reducer over the bridge's WebSocket messages
// (host/bridge/src/bridge.ts), plus the parser for kervixd's stats text.
// No React here, so it is unit-tested with node --test.

export type Tel = Record<string, number>;
export type GwMsg = { kind: string; id?: string; done?: boolean; [k: string]: unknown };
export type FeedEvent = { seq: number; t: number; source: string; msg: GwMsg };
export type Hello = { role: string; type: string; uid: number; prio: number; pid: number; fake?: boolean };
export type Escalation = {
  escalation_id: number;
  reason: string;
  reason_text: string;
  rule: string;
  remaining_ms: number;
  proposer_pid: number;
  intent: { action: string; actor: string; params: Record<string, unknown> };
};

export type Stats = {
  proposals: number;
  allow: number;
  escalate: number;
  block: number;
  p50us: number | null;
  p99us: number | null;
  minUs: number | null;
  maxUs: number | null;
  /** log2 buckets: [lo, hi) microseconds -> count */
  hist: { lo: number; hi: number; n: number }[];
  ledger: string | null;
  uptimeS: number | null;
  policy: string | null;
};

export type State = {
  connected: boolean;
  target: string;
  gateways: Record<string, { up: boolean; hello: Hello | null }>;
  authority: { up: boolean | null; since: number };
  telemetry: { tel: Tel | null; ageUs: number; plausible: boolean; at: number };
  stats: Stats | null;
  escalations: Escalation[];
  /** received at, per escalation: remaining_ms counts down locally between pushes */
  escAt: number;
  feed: FeedEvent[];
  fake: boolean;
};

export const FEED_MAX = 200;

export function initialState(): State {
  return {
    connected: false,
    target: "",
    gateways: {},
    authority: { up: null, since: Date.now() },
    telemetry: { tel: null, ageUs: 0, plausible: true, at: 0 },
    stats: null,
    escalations: [],
    escAt: Date.now(),
    feed: [],
    fake: false,
  };
}

export function parseStats(lines: string[]): Stats {
  const s: Stats = { proposals: 0, allow: 0, escalate: 0, block: 0, p50us: null, p99us: null, minUs: null, maxUs: null, hist: [], ledger: null, uptimeS: null, policy: null };
  for (const l of lines) {
    let m: RegExpMatchArray | null;
    if ((m = l.match(/^kervixd\s+uptime (\d+) s\s+policy (\S+ v[\d.]+)/))) {
      s.uptimeS = Number(m[1]);
      s.policy = m[2];
    } else if ((m = l.match(/^proposals (\d+)\s+ALLOW (\d+)\s+ESCALATE (\d+)\s+BLOCK (\d+)/))) {
      [s.proposals, s.allow, s.escalate, s.block] = m.slice(1, 5).map(Number);
    } else if ((m = l.match(/min ([\d.]+) us\s+max ([\d.]+) us/))) {
      s.minUs = Number(m[1]);
      s.maxUs = Number(m[2]);
    } else if ((m = l.match(/p50 < (\d+) us\s+p99 < (\d+) us/))) {
      s.p50us = Number(m[1]);
      s.p99us = Number(m[2]);
    } else if ((m = l.match(/^\s*\[\s*(\d+),\s*(\d+)\) us\s+(\d+)/))) {
      s.hist.push({ lo: Number(m[1]), hi: Number(m[2]), n: Number(m[3]) });
    } else if (l.startsWith("ledger ")) {
      s.ledger = l;
    }
  }
  return s;
}

/** Fill empty buckets between the first and last non-empty one (a histogram shows its gaps). */
export function denseHistogram(h: Stats["hist"]): Stats["hist"] {
  if (h.length === 0) return [];
  const byHi = new Map(h.map((b) => [b.hi, b.n]));
  const out: Stats["hist"] = [];
  for (let hi = h[0].hi; hi <= h[h.length - 1].hi; hi *= 2) out.push({ lo: hi === 1 ? 0 : hi / 2, hi, n: byHi.get(hi) ?? 0 });
  return out;
}

export function reduce(st: State, m: Record<string, unknown>): State {
  switch (m.type) {
    case "snapshot": {
      const gws = (m.gateways ?? {}) as State["gateways"];
      const tm = m.telemetry as GwMsg | null;
      return {
        ...st,
        connected: true,
        target: String(m.target ?? ""),
        gateways: gws,
        authority: (m.authority as State["authority"]) ?? st.authority,
        telemetry: tm ? telemetryOf(tm) : st.telemetry,
        stats: Array.isArray(m.stats) && m.stats.length ? parseStats(m.stats as string[]) : null,
        escalations: (m.escalations as Escalation[]) ?? [],
        escAt: Date.now(),
        feed: ((m.feed as FeedEvent[]) ?? []).slice(-FEED_MAX),
        fake: Object.values(gws).some((g) => g.hello?.fake),
      };
    }
    case "gateway": {
      const gateways = { ...st.gateways, [String(m.role)]: { up: m.up === true, hello: (m.hello as Hello) ?? null } };
      return { ...st, gateways, fake: Object.values(gateways).some((g) => g.hello?.fake) };
    }
    case "authority":
      return { ...st, authority: { up: m.up as boolean | null, since: Number(m.since ?? Date.now()) } };
    case "telemetry":
      return { ...st, telemetry: telemetryOf(m as GwMsg) };
    case "stats":
      return { ...st, stats: parseStats(m.text as string[]) };
    case "escalations":
      return { ...st, escalations: (m.items as Escalation[]) ?? [], escAt: Date.now() };
    case "feed": {
      const feed = [...st.feed, m.event as FeedEvent];
      return { ...st, feed: feed.length > FEED_MAX ? feed.slice(-FEED_MAX) : feed };
    }
    case "disconnected":
      return { ...st, connected: false };
    default:
      return st;
  }
}

function telemetryOf(m: GwMsg): State["telemetry"] {
  return { tel: (m.telemetry as Tel) ?? null, ageUs: Number(m.age_us ?? 0), plausible: m.plausible !== false, at: Date.now() };
}

export type Verdict = "ALLOW" | "ESCALATE" | "BLOCK";

/** The last decision about each intent, for the twin's "what just happened" toast. */
export function lastDecision(feed: FeedEvent[]): { verdict: Verdict; action: string; reason: string; t: number } | null {
  for (let i = feed.length - 1; i >= 0; i--) {
    const m = feed[i].msg;
    if ((m.kind === "decision" || m.kind === "resolution") && m.verdict) {
      const intent = m.intent as { action?: string } | undefined;
      return { verdict: m.verdict as Verdict, action: intent?.action ?? "?", reason: String(m.reason), t: feed[i].t };
    }
  }
  return null;
}

export const GEAR = ["P", "R", "N", "D"];

export function fmtParams(p: Record<string, unknown> | undefined): string {
  if (!p) return "";
  return Object.entries(p)
    .map(([k, v]) => `${k}=${typeof v === "string" && v.startsWith("sha256:") ? v.slice(0, 15) + "…" : String(v)}`)
    .join(" ");
}
