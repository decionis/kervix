// The ledger explorer's mirror against the REAL vehicle (used by tests/target/policy.sh):
// records and signed policy bundles fetched through the observer gateway, then verified.
import { Bridge } from "../../host/bridge/src/bridge.ts";

const b = new Bridge({ target: process.env.KX_TARGET ?? "127.0.0.1", listen: { host: "127.0.0.1", port: 0 }, log: () => {} });
await b.start();
for (let i = 0; i < 100 && !b.gw.observer.up; i++) await new Promise((r) => setTimeout(r, 100));
await b.syncLedger();
const v = (await b.ledger.verify()) as { verified: boolean; replay: { match: number; policies: string[] }; policies: unknown[]; findings: unknown[] };
const ok = v.verified && v.policies.length >= 1 && v.replay.policies.length >= 2;
console.log(`${ok ? "PASS" : "FAIL"}  ledger explorer mirror: ${b.ledger.info.records} capsules + ${b.ledger.info.policies.length} signed bundle(s) via the observer gateway; ` +
  `VERIFIED=${v.verified}, ${v.replay.match} decisions replayed under ${v.replay.policies.length} policies${ok ? "" : " " + JSON.stringify(v.findings)}`);
await b.stop();
process.exit(ok ? 0 : 1);
