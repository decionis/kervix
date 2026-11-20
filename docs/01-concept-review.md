# 01 — Concept Review: Kervix brief

> Status: **DRAFT for review** · Date: 2026-11-20 · Source: `brief.concept.md`
> Hackathon: **QNX Global Hackathon** (Devpost) · Submission deadline **Tue 2026-12-15, 14:00 ET** (25 days from today)

---

## 1. What the judges actually score

From the official rules (qnx.devpost.com/rules):

| Stage | What | Kervix implication |
|---|---|---|
| Stage One (pass/fail) | Fits the theme; really uses QNX 8.0 | The repo must **build for and run on QNX 8.0**. Naming QNX in the README is not enough. |
| Stage Two, **equally weighted** | **Technological Implementation**: real engineering effort, non-trivial, really runs on QNX 8.0 | Native resource managers, several channels, secpol, priority inheritance, benchmarks, tests |
| | **Design**: a *complete, coherent product experience*, not just a proof of concept | On-target CLI, live dashboard, driver HMI, policy toolchain, verifier: one story end to end |
| | **Potential Impact**: credible, specific case in a QNX market, and *why a real-time foundation like QNX* | UN R155/R156, EU AI Act Art. 12/14, ISO 26262/21434 alignment. Measured determinism. |
| | **Innovation & AI Creativity**: non-obvious, shows real understanding of the problem space | Governing a *real* LLM agent at the microkernel IPC boundary; deterministic replay of verdicts |
| Tie-break | Criteria in the order listed above | **Technological Implementation breaks ties.** Engineering depth beats polish. |
| Bonus: **Best Use of QNX-specific Tech** | Message passing, resource managers, microkernel, boot customization, real-time services, **security policies** | The brief's target. Secpol is named explicitly and the brief does not use it yet (see §3). |
| Bonus: **Best Codelab/Tutorial** | A tutorial for QNX 8.0 written during the submission period, judged on the same criteria | Cheap extra prize to target: we produce the material anyway. |
| Community Choice | Votes | The video and Devpost page quality matter. |

Hard submission requirements:
- Public repo with an OSI license that shows in the GitHub About section.
- Build/run instructions that state the QNX version, target (hardware or QEMU) and toolchain.
- Text description.
- YouTube video **under 3:00** showing the project **running on the device**.
- One category: **Automotive & Mobility**.
- Projects that existed before the hackathon must have been "significantly updated" and explain how. Kervix is new code, but **`@decionis/verify` is pre-existing**, so it must be disclosed as a dependency.

---

## 2. What is strong in the brief (keep)

1. **The problem is real and timely.** SDVs are adding LLM agents for diagnostics, cabin and OTA. Nothing standard sits between "agent decided" and "actuator moved".
2. **The ALLOW / ESCALATE / BLOCK triad with single-use, time-bound grants** is the right primitive, and it matches the Decionis protocol (Decide → Govern → Prove).
3. **A resource manager on a native QNX resource path** is the correct QNX-native shape. It is far better than a socket daemon.
4. **The audit trail is verifiable offline.** It gives OEMs and regulators a "black box for AI agents".
5. **Simulated SDV on QEMU first** reduces risk and keeps the target free of heavy runtimes.

---

## 3. Gaps, errors and risks to fix

| # | Issue in brief | Why it matters to judges | Fix in refined design |
|---|---|---|---|
| G1 | "unsafe commands are dropped **at the kernel boundary**" | On QNX, a resource manager is a **user-space process**; that is the point of a microkernel. A QNX judge will spot this at once and it costs credibility. | Make it *literally true* with **secpol**. The AI-facing process has **no kernel permission to `ConnectAttach()`** to the actuator or privileged Kervix channels. `open()` fails with `EACCES` inside `procnto` before any of our code runs. Kervix decides **policy**; the **kernel** enforces **topology**. |
| G2 | No use of QNX **security policies**, abilities or pathtrust | Named explicitly in the bonus-prize text, and the brief leaves them out | Per-process secpol types, per-channel types, `secpol_resmgr_attach()`, `secpol_transition_type()` to drop privileges, `procmgr_ability` lockdown |
| G3 | Single `/dev/decionis` endpoint | One channel means one trust level. AI traffic and driver approvals share a queue, so the AI can starve the driver. | **Four channels with separate secpol types** (agent, actuator, HMI, admin). **Priority inheritance** guarantees driver approvals and actuator redemption are never starved by an agent flood. |
| G4 | "SHA-256 hash-chained Decision Dossier ... verified with @decionis/verify" | `@decionis/verify` 0.5.0 does **not** verify a bare SHA-256 chain. It verifies **Ed25519**-signed artifacts, **Agent Action Capsule draft-04** (JCS, chained capsules, COSE_Sign1 producer envelopes) and **Agent-Safe Intent v1** hashes. As written, the demo claim would fail. | Emit **AAC draft-04 capsules** (chained, integer-only numbers), sign each with an **Ed25519 COSE_Sign1 producer envelope**, and bind every intent with **Agent-Safe Intent v1** hashing. Verified by the real `@decionis/verify` library, in CI. |
| G5 | Grant checked only when issued | **TOCTOU**: the car can start moving between grant (t₀) and actuation (t₀+200 ms) | **Interlock check at redemption.** Kervix re-evaluates the rule's interlock predicates against live telemetry when the grant is redeemed. Grants live for 250 ms by default. |
| G6 | Telemetry trusted as given | Stale or spoofed telemetry turns a safety gate into a rubber stamp | **Freshness watchdog** (fail-closed after 50 ms without data) and **plausibility checks**, for example gear=P with speed>0 means BLOCK and an anomaly capsule |
| G7 | No failure-mode story | Hard real-time judges ask "what happens when the gatekeeper crashes?" | **Fail-closed by construction.** Without Kervix nothing can redeem a grant. A supervisor restarts it. Recovery writes an `epoch_boundary` capsule. Shown live as `kill -9` in the video. |
| G8 | "Zero-allocation" claimed, not proven | Unverified claims hurt the Technological Implementation score | Pre-sized pools. A `malloc` guard aborts if anything allocates after init. A self-test proves it. |
| G9 | "Microsecond" claimed, not measured | Same | `kx-bench` measures with `ClockCycles()`. A `tracelogger` + System Profiler capture is the evidence. We publish **p50/p99/max on QEMU and on RPi4** and are honest about QEMU numbers. |
| G10 | Hand-wavy "AI agent" | The criterion is literally **"Innovation & AI Creativity"** | A **real Claude agent** (tool use) whose tools *are* vehicle actions. It shows a **prompt-injection attack** being blocked and the agent **adapting to the BLOCK reason**. A deterministic replay mode makes judging reproducible. |
| G11 | "VR dashboard" undefined | Scope-creep risk: VR is expensive and judges are rarely in headsets | **3D digital-twin dashboard** (WebGL), with **WebXR "Enter VR"** as a stretch toggle |
| G12 | Naming: Kervix vs `/dev/decionis` | Mixed branding dilutes recall | Product **Kervix**, paths `/dev/kervix/*`. Positioning: "a Decionis-protocol execution authority for QNX". See D1 in the open decisions. |
| G13 | No adoption path | Impact judges want "who would deploy this and how" | **Shadow mode** (observe, don't enforce), **policy-as-code** with tests, a **COVESA VSS** signal vocabulary, a 10-line C client API, an **MCP server** so any agent framework can be governed |
| G14 | Platform facts | **PPS is discontinued in QNX 8.0**, APS is discontinued, and HAM is deprecated (→ QPLMS). Using them would show outdated QNX knowledge. | Telemetry uses our own resmgr plus shared-memory seqlock and pulses. No PPS/APS/HAM dependency. |
| G15 | Missing roadmap items | No tests, no codelab, no video plan | Covered in `04-implementation-plan.md` and `05-demo-and-submission.md` |

---

## 4. Refined one-line pitch

> **Kervix is a kernel-enforced execution authority for software-defined vehicles. AI agents can *propose* anything; only actions that survive Kervix's real-time policy check receive a single-use grant. The QNX microkernel makes it physically impossible to reach an actuator any other way. Every decision is recorded as a signed, chained evidence capsule that anyone can verify and *replay* offline.**

Three-word frame for the video and Devpost: **Propose. Prove. Actuate.**

---

## 5. Positioning against alternatives (for the Impact narrative)

| Approach | Limitation | Kervix difference |
|---|---|---|
| LLM guardrails or system prompts | Probabilistic, bypassed by prompt injection, lives in the AI domain | Deterministic, enforced outside the AI domain, at the safety-domain IPC boundary |
| Middleware ACLs (SOME/IP, DDS security) | Static who-can-talk-to-whom. No context such as speed/gear/SoC, no evidence trail. | Context-aware per action, with time-bound single-use grants and signed evidence |
| Hypervisor partitioning alone | Isolates domains, but any allowed cross-domain call is trusted completely | Each cross-domain *action* is authorized individually |
| Vehicle event data recorders | Record physical events, not *who decided* or *why* | Records intent, policy version, telemetry, verdict, approver and effect |
| Cloud governance (incl. hosted Decionis) | Needs connectivity and adds latency, so it cannot gate an actuator at 100 km/h | Runs on the ECU in microseconds and works offline. Its evidence is compatible with the cloud verifier. |

---

## 6. Verdict on the brief

The core idea is strong and well matched to QNX. Five changes would move it from a good demo to a likely winner:
- Make "kernel-enforced" true with secpol.
- Make the proof claim true with AAC draft-04 and Ed25519.
- Prove real-time behaviour with numbers.
- Show a real AI agent being governed, prompt injection included.
- Wrap it in a complete product experience.

`02-product-design.md` and `03-architecture.md` specify these changes.
