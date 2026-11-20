# Kervix: Design Package (for review)

> **Kervix: kernel-enforced execution authority for software-defined vehicles, on QNX 8.0.**
> AI agents propose. Kervix decides in microseconds on live vehicle state. The QNX microkernel makes every other path to an actuator impossible. Every decision becomes a signed, chained, replayable evidence capsule.
> **Propose. Prove. Actuate.**

QNX Global Hackathon (Devpost) · Category **Automotive & Mobility** · Bonus targets **Best Use of QNX-specific Technologies**, **Best Codelab** · Deadline **2026-12-15 14:00 ET** · Plan submits **2026-12-14** · Solo · Dev host: Apple M1 macOS (via Docker) · Targets: QEMU x86_64 + Raspberry Pi 4.

| Doc | Purpose |
|---|---|
| [01-concept-review.md](01-concept-review.md) | What judges score, what's strong in the brief, 15 gaps/errors and how they're fixed |
| [02-product-design.md](02-product-design.md) | Problem, personas, tiered feature set mapped to judging criteria, action catalog, journeys, regulation mapping, metrics |
| [03-architecture.md](03-architecture.md) | Processes, secpol types, four-channel IPC, ABI structs, grant/escalation state machines, telemetry, policy, AAC/COSE proof, replay, timing budget, failure modes, threat model, agent design, repo layout |
| [04-implementation-plan.md](04-implementation-plan.md) | Spikes, day-by-day milestones M0–M4, estimates, cut lines, test strategy, risks, submission checklist |
| [05-demo-and-submission.md](05-demo-and-submission.md) | Live demo script, 2:45 video script, Devpost outline, codelab plan |
| [decisions.md](decisions.md) | Decision log (confirmed, default, spike-settled) + upstream AAC registry proposal |

## Most important changes from the brief

1. **"Kernel boundary" made true.** QNX **secpol** types each Kervix channel. An agent-type process gets `EACCES` from `procnto` when it tries to reach actuators or the redeem path. Kervix decides *policy*; the kernel enforces *topology*.
2. **Proof is compatible with `@decionis/verify`.** The brief's SHA-256 chain would not verify with it. The design uses **Agent-Safe Intent v1** + **AAC draft-04** capsules + **Ed25519 COSE_Sign1** envelopes.
3. **Grants are checked again at execution.** An interlock re-check at redemption closes the TOCTOU window.
4. **Fail-closed everywhere**: stale telemetry, crashed authority, full audit queue, escalation timeout.
5. **Measured real-time** with priority-inheritance QoS, so an agent flood cannot starve the driver's approval.
6. **A real Claude agent** is governed, including a **prompt-injection** scenario and re-planning based on BLOCK reasons. A scripted mode keeps the demo reproducible.
7. **Deterministic replay**: the verifier re-runs the same policy core and reproduces every verdict.
8. **QNX 8.0-accurate**: no PPS, APS or HAM, all of which are discontinued or deprecated in 8.0.
9. "VR dashboard" is reframed as a **3D digital twin**, with WebXR as a stretch goal.

## Decisions (see [decisions.md](decisions.md) for the full log)

**Confirmed by you (2026-11-20):**
- **Solo.** The plan is re-sequenced, with early cut triggers.
- **No hardware yet; RPi4 within a week.** QEMU is primary until about Nov 27, and RPi4 is a hard gate on Dec 3.
- **3D on-screen car (Must) + optional WebXR (Could).**
- **Register `follows` + `vehicle.*` upstream in AAC** (work item U1, `@decionis/verify` 0.6.0).

**Discovered:**
- **H1:** your Mac is an Apple M1 Pro, and **QNX SDP 8.0 doesn't support macOS or ARM hosts.** We use QNX's documented macOS workflow (Linux host tools in an x86_64 Docker container, QEMU on the Mac), with a cloud x86 Linux VM as the fallback. Spike S0 decides it on day 1.
- **H3:** QEMU on Apple Silicon is fully emulated, so **only RPi4 latency numbers are headlined.**

**Adopted by default (say if you disagree):** D1 `/dev/kervix` naming · D4 Claude `claude-opus-5-5` for live mode · D5 TypeScript host · D6 Apache-2.0 · D7 enter the Codelab bonus.

**Remaining before code:** your approval of this package. Then M0 starts (environment + spikes S0–S6).
