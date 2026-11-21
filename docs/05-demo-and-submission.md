# 05 — Demo, Video and Submission Plan

> Status: **DRAFT for review**. The video is the single most-viewed artifact: judges "are not required to watch beyond three minutes".

---

## 1. Demo setup

```
[Laptop]  dashboard (browser, full screen) + terminal (ssh into QNX)   ── Ethernet ──  [RPi4 running QNX 8.0]
                                                                                        └─ GPIO LED (optional)
Phone on a tripod: overhead shot of the RPi4 + LED, used for the B-roll "on device" proof
```

The laptop is the M1 MacBook, connected to the RPi4 through a USB-C Ethernet adapter.

Fallback rig: QEMU x86_64 on the same laptop. Every scene must also work there. On Apple Silicon, QEMU is emulated (TCG), so scene 5 (real time) is **always recorded on the RPi4**. If the RPi4 is unavailable by Dec 3, scene 5 shows only relative measurements (flood vs HMI ratio) and absolute µs claims are removed (`04` §3.3).

---

## 2. Live demo script (also the M3 acceptance run)

| # | Scene | Command / action | What the audience sees | Criterion |
|---|---|---|---|---|
| 0 | Boot | Power on RPi4 | QNX boot → `kx-supervisor` starts `kervixd`, `vsimd`, `sdv_actuatord`, `kxgw ×3`; `epoch_boundary` capsule | TI QX |
| 1 | Helpful (ALLOW) | Scenario "city 60 kph"; agent: "I'm cold" | Agent → `cabin.climate.set(225)` → ALLOW 23 µs → twin HVAC glows → decision + confirmed capsules | D |
| 2 | Injection (BLOCK) | Scenario "highway 110 kph"; agent reads the poisoned service bulletin | Agent proposes `ota.ecu.flash` → **BLOCK R156_NOT_SAFE_STATE** → agent tells the driver it will ask when parked | IA PI |
| 3 | Oversight (ESCALATE) | Scenario "parked + charging" | Agent re-proposes → **ESCALATE** → HMI card → driver approves → `resolved` (human) → grant → OTA progress glow → `confirmed` | PI D |
| 4 | Red team | `kx-rogue --all` in the QNX terminal | 5 attacks, 5 refusals; **`open(/dev/sdv/actuators/raw): Operation not permitted (EPERM)` from the kernel** | QX TI |
| 5 | Real time | `kx-bench --flood 10000` while approving an escalation | Histogram: PROPOSE p99 µs; HMI latency flat under flood | TI QX |
| 6 | Crash | `slay -9 kervixd` | Dashboard: **AUTHORITY OFFLINE — ACTUATION LOCKED**; agent action fails; respawn in ~ms; chain continues | TI PI |
| 7 | Proof | `kxctl export` → laptop offline → `npx kervix-verify dossier/` | VERIFIED: N capsules · signatures ✓ · chain ✓ · **replay N/N** → flip a byte → FAIL at #k | PI IA |

---

## 3. Video script (target 2:45; hard cap 2:59)

| Time | Visual | Voice-over (draft) |
|---|---|---|
| 0:00–0:12 | Black → a terminal line: `agent> ota.ecu.flash brake-ecu` with a speedometer at 110 km/h | "Cars now ship AI agents. What happens when one is tricked into flashing the brake controller at 110 km/h?" |
| 0:12–0:30 | Architecture diagram animates: AI domain → Kervix on QNX → actuators | "Kervix is an execution authority built natively on QNX 8.0. Agents can propose anything; only actions that pass a real-time policy check on live vehicle state get a single-use grant. The QNX microkernel makes every other path impossible." |
| 0:30–0:50 | Scene 1 (ALLOW), split screen with the RPi4 B-roll | "Helpful actions just happen, in microseconds." |
| 0:50–1:15 | Scene 2 (injection → BLOCK → agent adapts) | "Here a poisoned service bulletin tells the agent to flash firmware now. Kervix blocks it: unsafe state under UN R156. The agent reads the reason and re-plans." |
| 1:15–1:35 | Scene 3 (ESCALATE → driver approves) | "Parked and charging, the same update needs a human. The driver approves; that approval is signed into the record." |
| 1:35–2:00 | Scene 4 (kx-rogue) + secpol snippet on screen | "What if the agent skips Kervix? It can't. QNX security policies type every channel. The kernel itself refuses the connection. Forged grants, replays and fake services all fail." |
| 2:00–2:15 | Scene 5 + 6 quick cuts (histogram, kill -9, recovery) | "Decisions take tens of microseconds, even under a flood. Kill the authority and everything fails closed, then it recovers in milliseconds." |
| 2:15–2:35 | Scene 7 verify + tamper | "Every decision is an Ed25519-signed, chained Agent Action Capsule. Anyone can verify it offline and replay every verdict bit-for-bit." |
| 2:35–2:50 | Title card: Kervix · Propose. Prove. Actuate. · repo URL · "Built on QNX 8.0" | "Kervix: so AI can help drive the car without being trusted with it." |

Production notes:
- Record the scenes in scripted-agent mode for clean takes. Include one short clip labelled "live Claude" for authenticity.
- Show the QNX shell prompt and the `uname -a` / `pidin` output at least once, as proof it is running on the device.
- Burn in captions (many judges watch muted).
- No third-party music unless royalty-free with a licence noted.

---

## 4. Devpost page outline

1. **Inspiration**: AI agents in SDVs; one sentence on the regulatory pull (R155/R156, AI Act).
2. **What it does**: the three verdicts, kernel-enforced topology, signed and replayable evidence.
3. **How we built it**: QNX-specific list (resource managers, four secpol-typed channels, synchronous message passing + priority inheritance, pulses, shm seqlock, `secpol_transition_type`, `procmgr_ability`, tracelogger, qcrypto/slog2) and the host stack. **Disclosure:** "`@decionis/verify` is a pre-existing open-source (Apache-2.0) verifier we consume as a dependency; all Kervix code was written from Nov 20, 2026."
4. **Challenges**: secpol channel typing, TOCTOU interlocks, keeping signing off the hot path.
5. **Accomplishments**: measured numbers, the selftest table, replay 100%.
6. **What we learned**: QNX 8.0 changes (PPS/APS gone, io-sock, slog2).
7. **Upstream contribution**: registered the `follows` chain relation and the `vehicle.*` effect-type namespace in the Agent Action Capsule registry (`@decionis/verify` 0.6.1).
8. **What's next**: real CAN/SOME-IP gateway, QNX Hypervisor guest for the agent domain, HSM-backed keys, Kuksa/VSS databroker adapter, fleet dossier ingestion via hosted Decionis.
9. **Built with** tags: qnx, c, resource-manager, secpol, typescript, react, three.js, claude, mcp, ed25519.

---

## 5. Codelab (Best Codelab/Tutorial bonus)

**Title:** "Kernel-enforced least privilege on QNX 8.0: build a secpol-typed resource manager in 45 minutes"

| Step | Content |
|---|---|
| 1 | Set up SDP 8.0 + QEMU image with `mkqnximage`. Covers both a Linux host **and an Apple Silicon Mac** (Linux host tools in Docker + QEMU on macOS). This is a real pain point for many developers, which makes the codelab more valuable. |
| 2 | Minimal resource manager (`resmgr_attach`, `io_devctl`), test with a client |
| 3 | Switch to `secpol_resmgr_attach()`; write a policy with two process types |
| 4 | Type the channel per path; show `EPERM` for the wrong client type, even as root |
| 5 | Drop privileges: `secpol_transition_type()`, `procmgr_ability()` |
| 6 | Read the client's identity in the handler (`ConnectClientInfoExt`) |
| 7 | Priority inheritance demo: two clients at different priorities |
| 8 | Wrap-up: how Kervix uses this; links |

Published as `codelab/README.md` in the repo plus a public post (dev.to / Hashnode / Medium; choose one). It must be authored inside the submission window, and it is.
