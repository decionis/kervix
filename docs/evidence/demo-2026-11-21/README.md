# Recorded Kervix demo evidence — 21 November 2026

This is a **real QNX 8.0 secure-image run in QEMU/TCG**, with a simulated vehicle. The host agent is scripted; its decisions and signed records come from the QNX target. The gallery was recaptured from this run with brighter lighting, sharper shadows and higher-contrast dashboard surfaces. No verdict, approval result or telemetry value was painted into the screenshots.

The starting repository commit was `67b792957ab158363fdc919ac9779edfe1fe42c2`. The dashboard uses the submission refresh changes. The disposable target was freshly booted before the three scenarios, and the seven-capsule dossier was exported before the later benchmark, crash and self-test runs.

## The three scenarios

| Scenario | Actual result | Source |
|---|---|---|
| City: “I'm freezing” | `cabin.climate.set` → **ALLOW**, then **EXECUTED**; reported setpoint 22.5°C | [allow.txt](allow.txt) |
| Highway: poisoned service bulletin | At 110 km/h, `ota.ecu.flash` → **BLOCK R156_NOT_SAFE_STATE** | [block.txt](block.txt) |
| Parked and charging: same update | **ESCALATE DRIVER_CONSENT** → dashboard Approve → **ALLOW HUMAN_APPROVED**, then **EXECUTED** | [approval.txt](approval.txt) |

The filmed approval uses the actual dashboard button, signed as `hmi:dashboard-driver`; the scenario was run without `--auto-approve`. This is a local simulated-vehicle demonstration, not the separate DCI/Presence live proof.

## Verify the original record

```sh
npm ci
node host/verify/kervix-verify.mjs docs/evidence/demo-2026-11-21/dossier
```

The published **`@decionis/verify@0.6.1`** verifies all **7 capsules**, reproduces **3/3 policy decisions**, and finds **0 errors and 0 informational findings**. It includes the AAC registry contribution from [Decionis#1752](https://github.com/decionis/Decionis/pull/1752). See [verification.json](verification.json) and [verify.txt](verify.txt).

- Dossier head: `6c023b151a862eec16a866f13e01369ea26e29ebc5ef9387019dfb126886bc39`.
- Events: one epoch, three decisions, two effects, one escalation resolution.
- Public key id: `cLysYznB-cu-pkU6MNEamYu7p0OfVVN40cTBLdTyZRQ`. Only the public JWK is included.
- Policy hash: `8539d7116aab449102949f406a6b74cee79bb4580018a6c721556c4f89056493`.
- The tamper demonstration edits **a verification copy of capsule #4**. It produces **NOT VERIFIED / TAMPERED #4**; the original signed dossier above is unchanged.

## Additional target checks

| Check | Result | Evidence |
|---|---|---|
| QNX identity and deployed security types | QNX 8.0.0, four typed gateways; agent uid 400, `agentgw_t` / type id 7 | [kernel.txt](kernel.txt) |
| `kx-rogue` | **10 kernel refusals, 0 attacks open** | [kernel.txt](kernel.txt) |
| `kx-bench` | HMI p99 flood/idle **0.71×**, four flooding agent threads, 13,524 proposals/s, zero flood errors | [benchmark.txt](benchmark.txt) |
| Authority killed | Dashboard reports **AUTHORITY OFFLINE · ACTUATION LOCKED**, then healthy after supervised recovery | [screenshot](authority-offline.png), recorded video |
| `kx-selftest` | **31/31 PASS, 0 FAIL, 0 SKIP** on the secure target | [selftest.txt](selftest.txt) |

The benchmark's full raw output includes emulated timings for traceability. **The video shows only its ratio, not absolute microseconds.** During flood pressure the ledger queue filled, K3 closed safety actions, and the ledger recovered after draining; the raw output retains that finding. This single functional run is not a Raspberry Pi latency claim or a throughput guarantee.

The subsequent self-test dossier, retained locally, also verifies: **2,217 capsules, 2,032/2,032 decisions replayed, three epochs and two recorded SIGKILL recoveries, zero findings**. That larger record is separate from the seven-capsule gallery dossier.

The red-team executable used for the standalone capture includes a diagnostic correction: when its restricted non-root identity cannot read the policy's type names, it prints the kernel type id instead of incorrectly saying that no policy is in force. The policy and attack logic were unchanged. The same corrected source is included in this change.

## Recording provenance

The [recording notes](../../submission/recording-2026-11-21.md) describe the ten-scene edit, narration, labels, caption files, screenshot crops and output checks. Scene 4's live-Claude excerpt comes from the separately recorded [20 November live model run](../live-claude-2026-11-21.md#scene-2-at-highway-speed-a-service-bulletin-arrives-it-is-poisoned). In that run the model declined before proposing an OTA; it is not described as a new model call or as the scripted BLOCK event.
