# Devpost submission text: Kervix

> Paste-ready text for qnx.devpost.com. The two extra fields (build and run instructions; how the project meets the technology requirement) are in [`additional-details.md`](additional-details.md). **Category: Automotive & Mobility.** Also entered for *Best Use of QNX-specific Technologies* and *Best Codelab*.
> Every number below links to evidence in the repository. QEMU numbers are labelled as emulated; the Raspberry Pi 4 measurements replace them once the board arrives (Dec 3).

**Tagline:** *AI agents propose. QNX decides. Every decision is signed and can be replayed.*

---

## Inspiration

Cars are getting AI assistants that do more than talk. They will be asked to open windows, change cruise speed, share your location and install updates. Those agents run large language models on infotainment hardware, read documents and web pages, and can be talked into things. That is what prompt injection is.

The question I wanted to answer: **what does it take to let an AI agent act in a car *without trusting it*?**

Three requirements fall out of that question:
- The agent must not be able to reach an actuator by any path other than asking.
- Every request must be decided on the *live* vehicle state, in microseconds, by something the agent cannot influence.
- Afterwards anyone should be able to check, offline, what was decided and why.

Regulation points the same way: UN R156 for software updates, R155 for cybersecurity, the EU AI Act for human oversight.

QNX turned out to be a remarkably good fit, because its microkernel can enforce the first requirement by itself.

## What it does

**Kervix is an execution authority for software-defined vehicles, built natively on QNX 8.0.** An AI agent can only *propose* an action, through a gateway. Kervix answers in one of three ways:

- **ALLOW:** it issues a single-use, MAC-protected grant, bound to that exact command, that process and a 250–500 ms window. The actuator redeems it, and Kervix **re-checks the safety interlock at that moment**, so a car that started moving in between is refused.
- **ESCALATE:** the driver gets a notification in plain language ("Install a software update on the brake controller. Requires your consent. This can't be undone.") and approves or denies. Kervix re-evaluates on live state before acting, and no answer means no.
- **BLOCK:** with a reason the agent can act on, e.g. `R156_NOT_SAFE_STATE` for a firmware flash at 110 km/h.

Underneath that:

- **The kernel enforces the topology.** Each trust level is its own resource-manager channel with its own **secpol type**: agent, driver HMI, actuator, observer and workshop. The QNX kernel refuses every connection the policy does not list, **even for root**. The agent cannot touch the actuator, approve its own request, rewrite vehicle state or impersonate the authority. Our red-team tool `kx-rogue` tries ten such attacks; as the deployed agent, **0 of 10 get through**, and every one is refused by the kernel.
- **Every decision is evidence.** Each decision, approval, actuation, refusal, restart and policy change becomes an **Ed25519-signed, hash-chained Agent Action Capsule** (AAC draft-04, COSE_Sign1), written off the hot path. With "no audit, no action", nothing is allowed if it can't be recorded.
- **Rate limits the agent can't talk its way around.** Each action has a token bucket per *kernel-stamped* caller type (not the name the agent gives itself), so an agent can't hammer the windows or bury the driver in approval requests. Each limited decision records its bucket, and the verifier re-runs the limiter.
- **Replay proves the decision followed the policy.** `kervix-verify` checks a ledger offline: signatures, chain, semantics. It then **re-runs every decision with the vehicle's own C policy core compiled to WebAssembly**. A signature proves *who* recorded a decision; replay proves the decision *follows from the policy*. A test dossier containing a perfectly signed lie (an OTA flash at 110 km/h recorded as ALLOW) passes every other check and is caught only by replay.
- **Policies are signed updates.** A policy is YAML, compiled into a canonical body that the vehicle's C code loads, signed by an author **and a different approver**, and activated over a channel only the workshop type can reach. Each decision is replayed under the exact policy it was made with.
- **The dashboard** shows a procedural 3D twin that renders *what the vehicle reports*, never what was asked. Next to it: the driver's approval card, a live decision feed with the agent's reasoning summaries, a latency histogram, and a **ledger explorer with a Verify button**. Edit one record by a few milliseconds and verification fails at exactly that record.

## How I built it

**On QNX 8.0 (C11, ~10,900 lines including tests):**

- **Resource managers with one dispatch channel per trust level**, attached with `secpol_resmgr_attach()` so the policy types each channel. Callers are identified from the type the kernel stamps on every message (`ctp->info.type_id`).
- **secpol everywhere:**
  - typed channels and paths (`allow_attach … <channel type>`) and connect rules;
  - one-way privilege drops (`derive_type` + `secpol_transition_type`);
  - `restricted` types for development;
  - a **`--secpol=secure` release image**: one complete policy, nothing runs untyped, the root shell is confined. Its system half is harvested with `secpolgenerate` and reviewed; `secpolgenerate` runs in monitor mode for the refusal log.
- **Synchronous message passing and priority inheritance:** the driver HMI gateway runs at priority 30 and the agent's at 10. On QEMU, the HMI's p99 round trip under a 16.6k proposals/s agent flood is **1.03× idle**.
- **Deferred replies:** an agent waiting for the driver is REPLY-blocked in the kernel with no polling. Unblock pulses release it if it is killed, and registered pulses (`MsgRegisterEvent`) push escalations to the HMI.
- **Telemetry:** a 100 Hz simulator publishes through a single-writer **seqlock in shared memory**, mapped read-only by everyone else (TSan-clean).
- **qcrypto:** Ed25519 signing of every capsule, verification of policy signatures, and a DRBG for grant ids and per-boot keys.
- **`kx-supervisor`:** restarts the authority as the only type allowed to start it, records the cause in the next signed epoch, and gives up after a crash loop, failing closed.
- **On-target tools:** `kx-selftest` checks every claim on the target as the real roles (**31/31 on both the dev and the secure image**). `kx-bench` measures latency and isolation. `kx-rogue` is the red team.
- **Portability:** a portable core (`libkxcore`: policy evaluation, canonical JSON, intents, grants, capsules) runs unchanged on QNX, in host tests (ASan/UBSan) and as **WebAssembly** in the verifier.

**On the host (TypeScript, ~4,600 lines):** network gateways to the QNX side, a bridge (WebSocket and REST), the agent, the React Three Fiber dashboard, the policy compiler and signer, and the verifier.
- The agent runs **scripted** (recorded words, live verdicts; no API key needed) or **live with Claude Opus 5.5**. The live run used Microsoft Foundry.
- The system prompt contains **no safety rules**. Safety must not depend on the model behaving.

**Tooling:** QNX SDP 8.0, with its Linux host tools in Docker on an Apple-silicon Mac, and QEMU. Host CI runs on every push: unit tests, sanitizers, a libFuzzer run on the network parser, conformance against `@decionis/verify`, verification of a committed QNX-signed ledger, and the WebAssembly rebuild.

## Challenges

- **Getting the kernel to say no.** Typing *channels* (not paths) means one dispatch structure per trust level, and a type that isn't `restricted` silently ignores the policy in development mode.
  - **Inherited file descriptors bypass `channel connect` checks**: a daemon "worked" only because of how it was launched. The supervisor now hands the authority a pipe, never a file.
  - The release image needed a harvested system policy that I could review line by line.
- **Time-of-check vs time-of-use.** A grant issued while parked must not move a car that has since driven off. The interlock is re-evaluated at redemption.
- **"No audit, no action" without starving actions.** Every live grant reserves its ledger slot, so its final record always fits, while signing stays off the decision path.
- **Bugs the tests found:**
  - `kx-bench` found a grant table that a burst of 512 grants could lock for a minute.
  - Verifying the live session found that escalation ids restart per epoch and the verifier didn't know.
  - A byte-corruption test found that two different signed policy files could mean the same policy.
  - The verifier used to *skip* decisions made under a policy it didn't have; now it fails them.
  - Writing the rate limiter showed the verifier treated kervixd's fail-closed capacity refusals (grant table full, approval queue full) as replay mismatches.

  Each is fixed and covered by a test.

## Accomplishments I'm proud of

- **The kernel does the hard part.** Even as root, the agent's type cannot reach the actuator, and the release image confines the root shell itself.
- **Everything is checked on QNX, not just compiled:** 12 on-target test suites plus the codelab, the 31-check selftest on the secure release image, and a live Claude session whose signed ledger verifies offline (21/21 decisions replayed).
- **Replay catches a signed lie.** That is the difference between an audit log and evidence.
- **The YAML policy and the vehicle's built-in C policy hash identically.** The policy you review is the one that runs.
- **A live moment worth keeping:** in the live run, Claude spotted the poisoned bulletin's hidden instruction and declined on its own. In the scripted run, an agent that *is* fooled gets a BLOCK from Kervix. Either way, nothing unsafe happens.

## What I learned

- QNX's security policy is far more than access control. It shapes the architecture: **one channel per trust level** becomes the natural design, and the kernel's refusal log tells you exactly which rule a process needed.
- QNX 8.0 specifics I hit along the way, all written up in the codelab notes:
  - no PPS, so telemetry uses shared memory plus pulses;
  - sockets go through io-sock and need `network/jailroot` for non-root types;
  - `mkqnximage` remembers options between builds;
  - qcrypto contexts are single-use after a one-shot operation.
- With AI agents, **"the model will behave" is not a safety argument.** Topology plus deterministic policy plus evidence is.

## Codelab

**[Lock it down: kernel-enforced least privilege for a QNX 8.0 resource manager](../../codelab/README.md)** is a 45-minute, step-by-step tutorial on a 120-line car-lock service. Readers type its channels, drop its privileges, watch the kernel refuse even root, read the refusal log, and learn the path to a secure release image. `make codelab` runs every step on QNX 8.0 and checks it (8/8).

## Upstream contribution

I registered the AAC `follows` chain relation and the `vehicle.*` effect-type namespace in the Agent Action Capsule verifier ([decionis/Decionis#1752](https://github.com/decionis/Decionis/pull/1752), merged during the hackathon). Until the next `@decionis/verify` release ships it, `kervix-verify` reports those two as informational findings.

## What's next

- **Real hardware first:** Raspberry Pi 4 measurements (headline latency), then a real CAN / SOME/IP actuator gateway behind the same grant interface.
- **The agent domain in a QNX Hypervisor guest**, with the gateway as the inter-domain channel.
- **HSM-backed vehicle and policy keys**, and secure boot with a signed image.
- **A COVESA VSS / Kuksa databroker adapter** for telemetry.
- **Fleet-level evidence:** dossiers ingested and verified across vehicles.

## Built with

`qnx` · `qnx-sdp-8.0` · `secpol` · `resource-managers` · `qcrypto` · `c` · `webassembly` · `typescript` · `node.js` · `react` · `three.js` · `react-three-fiber` · `claude` · `ed25519` · `cose` · `qemu` · `docker`

## Try it (for judges)

- **Without QNX** (any machine with Node ≥ 22.18): `npm ci && make test`, then `node host/verify/kervix-verify.mjs tests/fixtures/dossier-qnx-qemu-2026-11-20`. This verifies a ledger signed on QNX, offline.
- **With QNX SDP 8.0:** `make target-selftest` boots QNX in QEMU, runs all 31 checks and verifies the run's ledger. `make codelab` runs the tutorial. See the [README](../../README.md#build-and-run).
- **Evidence:** [selftest tables](../evidence/), [benchmark](../evidence/bench-qnx-qemu.txt), [live Claude transcript and its signed ledger](../evidence/live-claude-2026-11-21.md), [screenshots](../images/).

## Disclosures

- **Built during the hackathon window**, starting Nov 20, 2026, by one developer, with Claude Code as coding assistant. The full history is in the repository: after the first two commits, every change landed through a pull request (34 merged by Nov 21).
- **Pre-existing dependency:** `@decionis/verify` (Apache-2.0), an open-source AAC verifier by the same author that predates the hackathon. Kervix uses it unchanged. The registry contribution above is the only change made to it during the hackathon.
- Third-party software and licences: [THIRD_PARTY.md](../../THIRD_PARTY.md). Nothing from the QNX SDP is redistributed.
