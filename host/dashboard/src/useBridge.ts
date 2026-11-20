// The dashboard's only link to the vehicle: the bridge WebSocket (/ws).
// Reconnects on its own; commands are answered by a "reply" with the same ref.
import { useCallback, useEffect, useReducer, useRef } from "react";

import { initialState, reduce, type GwMsg, type State } from "./model.ts";

type Reply = { ok: boolean; error?: string; messages?: GwMsg[] };

export function useBridge(): { state: State; send: (type: string, body: Record<string, unknown>) => Promise<Reply> } {
  const [state, dispatch] = useReducer(reduce, undefined, initialState);
  const ws = useRef<WebSocket | null>(null);
  const pending = useRef(new Map<string, (r: Reply) => void>());
  const nextRef = useRef(1);

  useEffect(() => {
    let closed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`;
      const sock = new WebSocket(url);
      ws.current = sock;
      sock.onmessage = (ev) => {
        const m = JSON.parse(String(ev.data)) as Record<string, unknown>;
        if (m.type === "reply") {
          const cb = pending.current.get(String(m.ref));
          pending.current.delete(String(m.ref));
          cb?.(m as unknown as Reply);
          return;
        }
        dispatch(m);
      };
      sock.onclose = () => {
        dispatch({ type: "disconnected" });
        for (const cb of pending.current.values()) cb({ ok: false, error: "bridge disconnected" });
        pending.current.clear();
        if (!closed) timer = setTimeout(connect, 1000);
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      ws.current?.close();
    };
  }, []);

  const send = useCallback((type: string, body: Record<string, unknown>) => {
    const sock = ws.current;
    if (!sock || sock.readyState !== WebSocket.OPEN) return Promise.resolve<Reply>({ ok: false, error: "bridge not connected" });
    const ref = `r${nextRef.current++}`;
    return new Promise<Reply>((resolve) => {
      pending.current.set(ref, resolve);
      sock.send(JSON.stringify({ type, ref, ...body }));
    });
  }, []);

  return { state, send };
}
