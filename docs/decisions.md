# Decision Log

> Status column: **Decided** = confirmed by owner · **Default** = recommendation adopted because the owner didn't object (can still be changed) · **Open** = needs an answer · **Spike** = settled by an M0 experiment

| ID | Date | Decision | Status | Consequence |
|---|---|---|---|---|
| Q1 | 2026-11-20 | **No hardware today. Raspberry Pi 4 expected within one week (≈ Nov 27).** | Decided | QEMU is the primary target for M0–M1. RPi4 bring-up is scheduled for Nov 27–28. All latency claims come from the RPi4 (QEMU on Apple Silicon is fully emulated). Hard gate: if no RPi4 by **Dec 3**, follow the QEMU-only plan (04 §3.3). |
| Q2 | 2026-11-20 | **Solo developer** | Decided | Solo schedule and early cut triggers (04 §4, §8). MCP server, GPIO LED and WASM verify moved to Could. QNX Screen HMI cut. |
| D1 | 2026-11-20 | Product **Kervix**, paths `/dev/kervix/*`, positioned as "Decionis-protocol compatible" | Default | — |
| D2 | 2026-11-20 | **3D on-screen car model (Must) + optional WebXR (Could)** | Decided | The 3D twin is promoted to Must. It is built procedurally in React Three Fiber from primitives (no external asset, no IP risk, ~1 day). WebXR is a toggle via `@react-three/xr`, added only after freeze criteria are green. |
| D3 | 2026-11-20 | **Register upstream in AAC:** chain relation `follows` and the effect-type namespace `vehicle.*` | Decided | New work item U1 (04 §5): spec registry text, `@decionis/verify` registry update with tests, release ≥ 0.6.0. Kervix pins that version. Disclosed on Devpost as an upstream contribution made during the hackathon. |
| D4 | 2026-11-20 | Live agent uses Claude `claude-opus-5-5` via your Anthropic API key. Scripted mode needs no key. | Default | — |
| D5 | 2026-11-20 | Host stack is TypeScript (npm workspaces; see H4) | Default | — |
| D6 | 2026-11-20 | License Apache-2.0 | Default | — |
| D7 | 2026-11-20 | Enter the Best Codelab bonus | Default | Written incrementally from spike notes (~30 min/day) and finished Dec 11 |
| **H1** | 2026-11-20 | **Build host.** The development machine is an Apple M1 Pro on macOS, and **QNX SDP 8.0 does not support macOS or ARM hosts.** We use QNX's documented macOS workflow: SDP + *Linux* host tools installed via QNX Software Center for macOS, and builds in an **x86_64 Ubuntu Docker container**. QEMU runs natively on the Mac (TCG emulation). | Default (spike S0) | Fallback if S0 fails by Sat Nov 21 evening: a cloud **x86_64 Ubuntu 24.04 VM**, used for building (and for QEMU with KVM if nested virtualization is available), via VS Code Remote-SSH. |
| H2 | 2026-11-20 | QEMU target arch: **x86_64 first** (best-documented `mkqnximage` path on Apple Silicon). **aarch64le compiled on every build** so RPi4 binaries never drift. | Default (spike S4) | `aarch64le` QEMU `virt` image is optional; it needs the extra `qemuvirt` + virtio packages. |
| H3 | 2026-11-20 | Benchmarks: **headline numbers only from RPi4.** QEMU/TCG results are labelled "functional, emulated, not representative". | Decided (follows from H1) | The video's latency scene is recorded on RPi4. |
| **S5** | 2026-11-20 | **Spike S5 PASSED.** Kervix-shaped AAC draft-04 capsules (epoch, ALLOW→confirm, BLOCK, ESCALATE, human resolve, grant replay, out-of-order confirm) pass `@decionis/verify` 0.5.0 Class 1 and Producer Envelope checks. A fixed CBOR template reproduces the pinned COSE_Sign1 vector byte-for-byte. A standalone minimal JCS matches the reference `jcsCanonicalize`. | Spike | Mapping frozen in `03-architecture.md` §8.2:<br>• An issued-not-yet-executed ALLOW **omits `verdict_class`** and carries an `effect` with `status: planned`, so no extra registry value is needed.<br>• Rule and constitution outcomes go in the standard **`constraints[]`**.<br>• Kervix data goes in the top-level **`evidence.kervix`** extension (the schema has `additionalProperties: true`).<br>• `disposition.authority` = policy hash; `epoch_id` = Kervix epoch.<br>• The only remaining findings are `info`: `follows` and `vehicle.*`, both fixed by U1. Reproduce with `npm run spike:s5`. |
| H4 | 2026-11-20 | Host JS workspace uses **npm workspaces** instead of pnpm (the local Homebrew pnpm is broken, and npm ships with Node, so judges need nothing extra) | Default | D5 is still TypeScript |

## Upstream AAC registry change (D3): proposed content

| Registry | Add | Semantics |
|---|---|---|
| `chain.relation` | **`follows`** | The parent is the immediately preceding capsule of the same producer stream (linear ledger order). It carries no claim of causality. The duplicate rule still applies: `references` must not repeat the parent. |
| `effect.type` | **namespace `vehicle.`**: any value matching `^vehicle\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$` | A physical or logical effect on a road vehicle. The v1 reference list is `vehicle.` + each Kervix catalog action id (e.g. `vehicle.ota.ecu.flash`, `vehicle.cabin.climate.set`). |

Verifier change (`packages/dossier-verify/src/aac-v04.ts`):
- Add `follows` to `REGISTRY.relation`.
- Add namespace matching for `effect.type`, so a `vehicle.*` value is registered (no `info` finding).
- Add tests for registered, unregistered and malformed `vehicle..x` values.
- Add a CHANGELOG entry and release **0.6.0**.
