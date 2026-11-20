#!/usr/bin/env node
// Screenshot a page with the local Chrome (GPU on, so WebGL renders), in real
// time, and report console errors. Uses the DevTools protocol over Node's
// built-in WebSocket: no extra dependencies.
//   node tools/screenshot.mjs <url> <out.png> [--wait ms] [--size 1600x1000] [--clip "css selector"] [--scale 2]
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args.splice(i, 2)[1] : d; };
const wait = Number(opt("--wait", "4000"));
const [w, h] = opt("--size", "1600x1000").split("x").map(Number);
const clipSel = opt("--clip", "");
const scale = Number(opt("--scale", "1"));
const [url, out] = args;
if (!url || !out) { console.error("usage: screenshot.mjs <url> <out.png> [--wait ms] [--size WxH]"); process.exit(2); }

const chrome = process.env.CHROME ?? (process.platform === "darwin" ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "google-chrome");
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "kx-shot-"));
const port = 9300 + Math.floor(Math.random() * 500);
const proc = spawn(chrome, ["--headless=new", "--enable-gpu", "--hide-scrollbars", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, `--window-size=${w},${h}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === "page"); } catch {}
}
if (!target) { proc.kill(); console.error("chrome did not start"); process.exit(1); }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let n = 0;
const waiting = new Map();
const errors = [];
ws.addEventListener("message", (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m.result); waiting.delete(m.id); }
  if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") errors.push(m.params.args.map((a) => a.value ?? a.description).join(" "));
  if (m.method === "Runtime.exceptionThrown") errors.push(m.params.exceptionDetails.exception?.description ?? m.params.exceptionDetails.text);
});
const cdp = (method, params = {}) => new Promise((r) => { const id = ++n; waiting.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
await cdp("Runtime.enable");
await cdp("Page.enable");
await cdp("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: scale, mobile: false });
await cdp("Page.navigate", { url });
await sleep(wait);
let clip;
if (clipSel) {
  const r = await cdp("Runtime.evaluate", { expression: `JSON.stringify((() => { const e = document.querySelector(${JSON.stringify(clipSel)}); if (!e) return null; const b = e.getBoundingClientRect(); return { x: b.x, y: b.y, width: b.width, height: b.height }; })())`, returnByValue: true });
  const box = JSON.parse(r.result.value ?? "null");
  if (!box) errors.push(`--clip: no element matches ${clipSel}`);
  else clip = { ...box, scale: 1 };
}
const shot = await cdp("Page.captureScreenshot", clip ? { format: "png", clip } : { format: "png" });
fs.writeFileSync(out, Buffer.from(shot.data, "base64"));
ws.close();
const exited = new Promise((r) => proc.once("exit", r));
proc.kill();
await Promise.race([exited, sleep(3000)]);
try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* temp dir */ }
console.log(`wrote ${out}${errors.length ? `; console errors:\n  ${errors.join("\n  ")}` : "; no console errors"}`);
