#!/usr/bin/env node
// kervix-bridge: host/bridge entry point.
//   node host/bridge/src/main.ts [--target HOST] [--listen HOST:PORT] [--hz N] [--static DIR]
//   env: KX_TARGET (default 127.0.0.1: the QEMU port forwards), KX_BRIDGE_LISTEN
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Bridge } from "./bridge.ts";

const args = process.argv.slice(2);
const opt = (name: string, dflt?: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
if (args.includes("--help")) {
  console.log("usage: kervix-bridge [--target HOST] [--listen HOST:PORT] [--hz N] [--static DIR]");
  process.exit(0);
}
const [lh, lp] = (opt("--listen", process.env.KX_BRIDGE_LISTEN ?? "127.0.0.1:8787") as string).split(":");
const here = path.dirname(fileURLToPath(import.meta.url));
const dflt = path.resolve(here, "../../dashboard/dist");
const bridge = new Bridge({
  target: opt("--target", process.env.KX_TARGET ?? "127.0.0.1") as string,
  listen: { host: lh, port: Number(lp) },
  telemetryHz: Number(opt("--hz", "10")),
  staticDir: opt("--static", dflt),
});
await bridge.start();
const bye = async () => {
  await bridge.stop();
  process.exit(0);
};
process.on("SIGINT", bye);
process.on("SIGTERM", bye);
