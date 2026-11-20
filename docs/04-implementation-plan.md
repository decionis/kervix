# 04 — Implementation Plan: Kervix (solo edition)

> Status: **DRAFT v2 for review. No code until approved.** Revised 2026-11-20 after the decisions in `decisions.md` (solo, no hardware yet, RPi4 within a week, macOS/M1 dev machine).
> Window: **Fri 2026-11-20 → Mon 2026-12-14 (submit)**. Tue 12-15 (deadline 14:00 ET) is buffer only.
> Capacity: 1 developer × 25 calendar days, with Claude Code doing most of the implementation and the developer reviewing, testing on target and making decisions.

---

## 1. Milestones at a glance

| Milestone | Dates | Exit criteria (demoable) |
|---|---|---|
| **M0 Foundations** | Fri Nov 20 – Sun Nov 22 | macOS→Docker→qcc build works; QNX boots in QEMU on the Mac; spikes S0–S6 resolved; repo + host CI green; RPi4 ordered |
| **M1 Authority MVP** | Mon Nov 23 – Fri Nov 27 | On QEMU: `kxctl propose` → ALLOW/BLOCK/ESCALATE from live vsimd telemetry; grant → actuatord → state change; replay/expiry/interlock rejected |
| **HW-1 RPi4 bring-up** | Fri Nov 27 – Sat Nov 28 (evenings) | QNX 8.0 image boots on RPi4; ssh; deploy script; M1 binaries run unchanged |
| **M2 Proof + Hardening** | Sat Nov 28 – Thu Dec 3 | Signed AAC ledger passes `kervix-verify` + `@decionis/verify`; secpol enforced; crash recovery; `kx-rogue` + `kx-selftest` PASS on QEMU **and RPi4**; upstream AAC registry released |
| **M3 Experience** | Fri Dec 4 – Wed Dec 9 | Bridge, 3D dashboard, HMI approval, scripted + live Claude agent, RPi4 benchmarks, replay verification |
| **Feature freeze** | **Wed Dec 9, 23:59** | Bug fixes, docs and video only after this |
| **M4 Ship** | Thu Dec 10 – Mon Dec 14 | Quickstart validated cold; codelab published; video on YouTube; **Devpost submitted Mon Dec 14** |

---

## 2. Development environment (Apple M1 Pro, macOS)

QNX SDP 8.0 supports only x86_64 Windows/Linux hosts. We follow QNX's documented macOS workflow (see `decisions.md` H1):

```
macOS (M1)                                                   
├── QNX Software Center (macOS)  → ~/qnx800  (SDP 8.0 + "QNX SDP Host Tools (Linux 64-bit)") + license
├── Docker Desktop  → container "qnx-build" (Ubuntu 24.04, linux/amd64 via emulation), mounts ~/
│      └── qcc / q++ / mkqnximage / CMake  → builds target/ for x86_64 + aarch64le, builds QEMU image
├── QEMU (Homebrew)  → boots QNX x86_64 image (TCG), user-mode net with hostfwd:
│      ssh 2222→22, 7301-7303→kxgw roles
├── Node 22.18+ (npm; TypeScript runs via Node's type stripping)  → host/ (bridge, dashboard, agent, verify, kxpolicy) runs natively on macOS
└── RPi4 (from ~Nov 27) on Ethernet (USB-C Ethernet adapter or same LAN) → ssh/scp deploy
```

Ergonomics:
- `make target` runs `docker exec qnx-build cmake --build …` for both arches.
- `make qemu` boots the image.
- `make deploy-qemu` and `make deploy-rpi` scp binaries + secpol + startup script and restart the services.
- `make selftest-qemu` and `make selftest-rpi`.
- Host code (TS, and `libkxcore` host tests in native clang) builds directly on macOS. **`libkxcore` must stay OS-free** so its tests run natively at full speed.

### 2.1 Hardware shopping list (order today)

| Item | Note |
|---|---|
| **Raspberry Pi 4 Model B, 4 GB** | The QNX 8.0 quick-start target image is for **RPi4**. Do not substitute a Pi 5 unless QNX 8.0 support is confirmed. |
| Official USB-C 5V/3A PSU | Under-voltage causes flaky benchmarks |
| microSD 32 GB, A1/A2 class | + USB card reader if the Mac has none |
| Ethernet cable + **USB-C Ethernet adapter** for the Mac | Direct link or same LAN as the Mac |
| *Optional:* USB-to-TTL serial cable (3.3 V) | Console access if networking misbehaves during bring-up |
| *Optional:* 1 LED + 330 Ω resistor + 2 jumper wires | C-tier physical actuation |
| *Optional:* small case with fan | Thermal stability for benchmark runs |

---

## 3. M0: Foundations and spikes (Fri Nov 20 – Sun Nov 22)

Time-boxed. If a spike fails, take the fallback immediately.

| Spike | Day | Question | Box | Fallback |
|---|---|---|---|---|
| **S0** | Fri | SDP + Linux host tools on Mac; Docker x86_64 container builds `hello.c` with `qcc -Vgcc_ntox86_64` and `-Vgcc_ntoaarch64le`; `mkqnximage --type=qemu --arch=x86_64 --build` in the container; QEMU boots on the Mac; ssh via hostfwd | 6 h | **Cloud x86_64 Ubuntu 24.04 VM** via VS Code Remote-SSH (decide by Sat evening at the latest) |
| **S6** | Fri | CMake toolchain files (`cmake/qnx-x86_64.cmake`, `cmake/qnx-aarch64le.cmake`) inside the container | 2 h | QNX recursive make |
| **S1** | Sat | `secpol_resmgr_attach()` with **per-path channel types** + `allow … channel connect` → `EACCES` for the wrong type; secpol compiled into the image; `MsgRegisterEvent` for pulses | 6 h | One channel per process (split `kervixd` + `kervix-redeemd` sharing state via shm). Keeps kernel enforcement. |
| **S2** | Sat | `ConnectClientInfoExt(_NTO_CLIENTINFO_GETTYPEID)` returns the client's secpol type id | 2 h | uid/gid per process + node permissions |
| **S3** | Sun | qcrypto on 8.0: Ed25519 sign, SHA-256, HMAC, RNG | 3 h | Vendored Monocypher + `/dev/random` |
| **S4** | Sun | io-sock + QEMU user-net port forwards for 3 gateway ports; startup script runs our services at boot | 2 h | Manual start via ssh |
| **S5** | Sun | In TS: produce 1 AAC draft-04 capsule (with `evidence` member, `follows` relation, `vehicle.*` effect) + COSE envelope → `@decionis/verify` Class 1 + envelope pass; settle `verdict_class` for issued-not-executed | 3 h | Evidence via `references` digests + sidecar |

Also in M0:
- **Order the RPi4** (Fri morning).
- Create the GitHub repo:
  - Apache-2.0 license visible in About.
  - README stub.
  - `.github/workflows/host.yml` covering macOS/Linux host tests.
- `catalog/catalog.yaml` + codegen (C headers, TS types, tool schemas).
- Keep `codelab/NOTES.md` as you go. Every secpol gotcha becomes codelab material.

**M0 exit (Sun night):**
- `hello_resmgr` attached via secpol in QEMU, and a rogue type is denied.
- Spike results recorded in `decisions.md`.
- The CMake build produces binaries for both arches.

### 3.3 QEMU-only contingency (if RPi4 slips past Dec 3)

- The video shows QNX in QEMU, which is allowed by the rules ("any target hardware QNX supports, including QEMU").
- The latency scene becomes "bounded by design + measured cycle counts in QEMU (emulated)". Measure relative effects only (agent flood vs HMI latency ratio), which stay meaningful under emulation.
- Remove absolute µs claims from the README and Devpost.

---

## 4. Day-by-day plan (solo)

Legend:
- **AM** = deep work block (target C, the hard part).
- **PM** = second block (host TS / integration).
- **EVE** = short tasks (hardware, docs, codelab notes).

### M1: Authority MVP

| Day | AM | PM | EVE |
|---|---|---|---|
| Mon Nov 23 | `libkxcore`: ABI structs, catalog, pure `kx_eval`, constitution K1–K4 | Host unit tests for eval truth tables; `kxpolicy` v0 (YAML → `.kxp`, unsigned) | codelab notes |
| Tue Nov 24 | `libkxcore`: bounded JCS writer, Agent-Safe Intent binding + hash, grant table, SPSC ring | Golden vectors vs `@decionis/verify intent`; `kxpolicy test` runner (host CLI shim of `libkxcore`) | — |
| Wed Nov 25 | `vsimd`: 100 Hz model, shm seqlock, pulse subscribers, `/dev/sdv/sim/ctl` scenarios | Synthetic drive-cycle generator; scenario files | — |
| Thu Nov 26 | `kervixd`: resmgr skeleton, PROPOSE on ch_agent, telemetry view, freshness watchdog, `/dev/kervix/stats` | `deploy-qemu` + `m1.sh` acceptance script | — |
| Fri Nov 27 | `sdv_actuatord` + REDEEM (7 checks incl. interlock) + EFFECT; `libkervix`; `kxctl propose/stats/tail` | **M1 acceptance on QEMU** (6 tests below) | **HW-1:** flash the RPi4 image if it has arrived |

**M1 acceptance (`tests/target/m1.sh`):**
1. Parked: `body.door.unlock` → ALLOW → executed → telemetry changes.
2. At 60 kph → BLOCK `R_MOVING`.
3. Replayed grant → `KX_E_SPENT`.
4. Redeem after 300 ms → `KX_E_EXPIRED`.
5. Shift to D between grant and redeem → `KX_E_INTERLOCK`.
6. vsimd stopped → BLOCK `TELEMETRY_STALE` within 50 ms.

### M2: Proof and hardening

| Day | AM | PM | EVE |
|---|---|---|---|
| Sat Nov 28 | Ledger writer thread: capsule JCS, capsule_id, Ed25519 COSE_Sign1 template, key generation, JWK export | `kervix-verify` v0: Class 1 + envelope + key pinning + chain continuity | **HW-1:** RPi4 network/ssh, `deploy-rpi`, run M1 tests on RPi4 |
| Sun Nov 29 | Ledger file format, fsync batching, torn-tail recovery, `epoch_boundary`; K3 ring pressure | `kervix-verify`: semantic invariants + tamper tests | **U1:** upstream AAC registry change in the Decionis repo (`follows`, `vehicle.*`) + tests |
| Mon Nov 30 | **secpol** full policy, four channels, privilege drop, `/dev/sdv/actuators/raw`, image startup | Conformance CI: committed dossier verified on each push | U1: release `@decionis/verify` 0.6.0; pin it in Kervix |
| Tue Dec 1 | Escalations: queue, `ionotify`, RESOLVE, deferred AWAIT, timeout, HMI priority | `kxpolicy` signed bundles (author ≠ approver) + POLICY_ACTIVATE client | — |
| Wed Dec 2 | `kx-supervisor`, `kx-rogue` (5 attacks), malloc guard, rate limiter, shadow mode | **Replay:** `kervix-verify --replay` via host build of `libkxcore` | — |
| Thu Dec 3 | **`kx-selftest`**: all scenarios with a PASS/FAIL table, on QEMU + RPi4; fix aarch64 issues | Buffer / catch-up | **Gate:** RPi4 working? If not, switch to §3.3 |

**M2 acceptance:**
- `kx-selftest` 100% PASS on QEMU and RPi4.
- `kervix-verify` reports signatures 100%, chain continuous and replay 100%.
- `@decionis/verify` 0.6.0 passes every capsule and envelope with **no `info` findings for `follows` or `vehicle.*`**.

### M3: Experience

| Day | AM | PM | EVE |
|---|---|---|---|
| Fri Dec 4 | `kxgw` (3 roles, fixed-schema JSON ⇄ ABI, 4 KiB bound, per-role priority) | `host/bridge`: TCP roles → WebSocket events, scenario control | — |
| Sat Dec 5 | `kx-bench` + histograms on **RPi4**; `tracelogger` capture → `docs/evidence/` | Dashboard shell: layout, telemetry panel, decision feed, latency histogram | — |
| Sun Dec 6 | Bug bash on target; `kxctl export` | **3D twin** (procedural R3F car: body, 4 doors, windows, wheels, light bars, charge port, OTA glow); escalation card; "AUTHORITY OFFLINE" state | — |
| Mon Dec 7 | `host/agent` scripted mode + scenario transcripts | `host/agent` live Claude tool loop; reasoning summary → dashboard | — |
| Tue Dec 8 | Prompt-injection scenario + adaptive re-plan | Ledger explorer + Verify button | codelab draft 1 |
| Wed Dec 9 | **Full demo run ×2 on RPi4** + once offline in scripted mode | Polish. If all green: WebXR toggle (`@react-three/xr`), time-boxed to 3 h. | **FREEZE 23:59** |

### M4: Ship

| Day | Tasks |
|---|---|
| Thu Dec 10 | README: pitch, GIF, architecture diagram, **Build & Run** (SDP 8.0 version, QEMU x86_64 + RPi4 aarch64le, qcc/gcc 12 + CMake, the macOS/Docker *and* native Linux paths), troubleshooting. Cold quickstart dry-run. |
| Fri Dec 11 | Codelab final + publish (repo `codelab/` + public post). Devpost text. Evidence page. `THIRD_PARTY.md`. |
| Sat Dec 12 | **Record the video** (screen capture + phone B-roll of RPi4). Edit to ≤ 2:50 with burned-in captions. Upload publicly to YouTube. |
| Sun Dec 13 | Final repo audit (§11 checklist). Tag `v1.0.0`. Re-verify the committed dossier from the tag. |
| Mon Dec 14 | **Submit on Devpost.** Ask one person to try the quickstart cold. |
| Tue Dec 15 | Buffer for submission blockers only. |

---

## 5. Work breakdown (solo, person-days)

| Area | Est. | Tier |
|---|---|---|
| Env on macOS + spikes (S0–S6) | 3.0 | M |
| `libkxcore` (policy, JCS, intent, grants, ring) + tests | 2.5 | M |
| `vsimd` | 1.0 | M |
| `kervixd` (4 channels, propose/redeem/escalate/policy/dossier/stats) | 3.0 | M |
| `sdv_actuatord` + `libkervix` + `kxctl` | 1.0 | M |
| Ledger + signer + recovery | 2.0 | M |
| secpol + supervisor + rogue + selftest | 2.0 | M |
| `kxgw` | 0.75 | M |
| `kervix-verify` + replay | 1.5 | M / S |
| `kxpolicy` (compiler, signer, tests) | 0.75 | S |
| Bridge | 0.75 | M |
| Dashboard 2D panels | 1.5 | M |
| **3D twin (procedural)** | 1.0 | **M** (D2) |
| Agent (scripted + live) + injection | 1.25 | M / S |
| RPi4 bring-up | 0.5 | M |
| Bench + tracelogger evidence (RPi4) | 0.5 | S |
| **U1** upstream AAC registry + verifier release | 0.5 | S (D3) |
| Docs, codelab, video, submission | 3.0 | M |
| **Total** | **≈ 26.5 pd** | Against 25 calendar days. Tight: it works only because cut triggers fire early (§8) and Claude Code writes most of the code. |

Moved out because of solo capacity: MCP server (S→**C**), GPIO LED (**C**), WASM in-browser verify (**C**), WebXR (**C**, 3 h box on Dec 9), privacy actions (**C**), QNX Screen on-target HMI (**cut**), extensive fuzzing (smoke-level only).

---

## 6. Upstream contribution U1 (Decionis repo)

In `~/develop/products/Decionis`, on a feature branch, opened as a PR for your review (Kervix work never pushes to Decionis directly):
1. Spec text: add the `follows` relation and the `vehicle.` effect-type namespace to the AAC draft-04 registry section.
2. `packages/dossier-verify/src/aac-v04.ts`: add `follows` to `REGISTRY.relation`; namespace match for `effect.type`.
3. Tests: registered, unregistered and malformed values; one full Kervix-shaped capsule fixture.
4. CHANGELOG, then release **0.6.0** to npm (your publish step).
5. Kervix's `host/verify` pins `@decionis/verify@^0.6.0`. Until it is published, it uses a local tarball.

---

## 7. Daily rhythm (solo)

- Start of day: read yesterday's `kx-selftest` / CI result and pick the day's AM goal from §4.
- End of day: commit, push, update `docs/progress.md` (one line per day: done / slipped / cut). Add codelab notes.
- **Checkpoint rule:** if the AM goal slips into a second day, apply the next cut from §8 immediately.

---

## 8. Cut lines (pre-agreed, applied in order)

| Checkpoint | Trigger | Cut |
|---|---|---|
| Sat Nov 21 EOD | S0 not booting QNX on the Mac | Switch to the cloud x86 VM (no cut, but costs about half a day) |
| Fri Nov 27 EOD | M1 not passing | `kxpolicy` signatures → hash-only; shadow mode; rate limiter |
| Thu Dec 3 EOD | M2 not passing | Replay → reduced to verdict-only (not reason/rule); U1 release slips (use a local tarball and disclose) |
| Thu Dec 3 EOD | No RPi4 | §3.3 QEMU-only contingency |
| Mon Dec 7 EOD | Agent not working live | Scripted agent only (verdicts are still real and live); the live clip is dropped |
| Tue Dec 8 EOD | Dashboard incomplete | Ledger explorer → CLI verify shown in the terminal; the 3D twin keeps doors/windows/OTA glow only |
| Wed Dec 9 freeze | Anything half-done | Removed from README/Devpost claims, never shipped half-working |

**Never cut (Must):**
- `kervixd` + `vsimd` + `actuatord` + `kxgw`.
- Grants + interlock.
- secpol channels.
- Escalation.
- Signed AAC ledger + `kervix-verify`.
- `kx-rogue` + `kx-selftest`.
- Scripted agent.
- 3D dashboard (procedural).
- Runs on QNX 8.0 (QEMU, and RPi4 if available).
- README + video.

---

## 9. Quality and testing strategy

| Layer | Tooling | What |
|---|---|---|
| Unit (host, native macOS clang) | CTest + a minimal C harness | Policy truth tables, predicate ops, JCS byte-exactness, grant table lifecycle, ring wraparound |
| Fuzz (host, smoke) | libFuzzer + ASan, 10 min per target in CI-nightly | `libkxcore` intent validation; `kxgw` line parser (built host-side) |
| Conformance | Node + `@decionis/verify` | Intent hashes, capsule ids, COSE envelopes, full committed dossier |
| Policy | `kxpolicy test` | One fixture per rule and per constitution invariant |
| Target integration | `kx-selftest` | Journeys J1–J6 + 5 attacks; PASS/FAIL + timings |
| Performance | `kx-bench` (RPi4) | p50/p99/max PROPOSE/REDEEM; HMI latency under flood; recovery time |
| E2E | Scripted agent scenarios | Dashboard sequence + dossier verifies |
| Static | `-Wall -Wextra -Werror`, clang-tidy (host), `tsc --strict`, eslint | |

Target C rules:
- C11.
- No VLAs. No recursion.
- No `malloc` after init (guarded).
- Constant loop bounds.
- `_Static_assert` on every IPC struct.
- All return codes checked.
- `slog2` logging.

---

## 10. Risk register (updated)

| # | Risk | L | I | Mitigation |
|---|---|---|---|---|
| R0 | **macOS/M1 is unsupported as an SDP host**; the Docker emulation path is slow or broken | M | H | QNX's documented Docker workflow (S0); cloud x86 VM fallback decided by Sat Nov 21. Host code and `libkxcore` tests stay native on macOS. |
| R1 | Secpol per-channel typing harder than documented | M | H | S1 on day 2 with a fallback that keeps kernel enforcement |
| R2 | qcrypto lacks Ed25519 | M | M | Monocypher fallback behind `kx_crypto.h` |
| R3 | RPi4 late or image issues | M | M | QEMU-only contingency §3.3; serial cable for bring-up debugging |
| R4 | AAC mapping ambiguity | L | M | S5 + U1 (you own the spec) |
| R5 | **Solo bandwidth** (26.5 pd / 25 d) | H | H | Early cut triggers; scripted agent before live; procedural 3D (no asset work) |
| R6 | LLM nondeterminism in the video | M | M | Scripted takes; labelled live clip |
| R7 | QEMU/TCG latency meaningless | H | L | Headline RPi4 only (H3) |
| R8 | Eligibility: pre-existing Decionis code | L | H | New Kervix repo; `@decionis/verify` disclosed as a dependency; U1 disclosed as an upstream contribution |
| R9 | Asset/IP issues | L | M | Procedural car; synthetic drive cycle; no brands |
| R10 | Judges can't reproduce (SDP license, Mac/Linux differences) | M | M | Both host paths documented; committed evidence; check whether a prebuilt QEMU image may be redistributed under the license |
| R11 | Docker Desktop on macOS flagged or broken by an OS update | L | M | Pin a working Docker version; the cloud VM fallback covers it |

---

## 11. Submission checklist (from the official rules)

- [ ] Public GitHub repo, **Apache-2.0 LICENSE detected in the About section**
- [ ] Repo shows it **really builds for/runs on QNX 8.0** (CMake toolchain, buildfile, secpol, target binaries, on-target logs)
- [ ] Build/run instructions state the **QNX version**, **targets (QEMU x86_64, RPi4 aarch64le)** and **toolchain (SDP 8.0 qcc/gcc 12, CMake)**, with both the Linux-host and macOS-Docker paths
- [ ] Category: **Automotive & Mobility**
- [ ] Text description of features and functionality
- [ ] **YouTube video < 3:00, public**, with footage of it running **on the device**
- [ ] "Built during the hackathon" statement; `@decionis/verify` disclosed as pre-existing; U1 listed as an upstream contribution
- [ ] Bonus: codelab URL (authored in the window, QNX 8.0 task)
- [ ] `THIRD_PARTY.md` (Monocypher if used, npm deps)
- [ ] No secrets in the repo (keys generated at first boot; `.gitignore` covers `keys/`, `.env`)
