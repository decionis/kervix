# Submission checklist (QNX Global Hackathon 2026, Devpost)

> Deadline **Tue Dec 15, 14:00 ET**. Plan: feature freeze Wed Dec 9, submit **Mon Dec 14** (`04-implementation-plan.md`).
> Status as of **Sat Nov 21**. ✅ done · 🟡 in progress / scheduled · 👤 owner action (needs your accounts or hardware) · ⛔ blocker

## Required by the rules

| Requirement | Status | Evidence / what's left |
|---|---|---|
| Public GitHub repository | ✅ | `decionis/kervix` is public (Nov 21). See "Going public" below for the key rotation. |
| Open-source licence visible in the repo's About section | ✅ | `LICENSE` is the canonical Apache-2.0 text; GitHub detects it as `Apache-2.0`. |
| Really builds for / runs on QNX 8.0 | ✅ | CMake toolchains (`cmake/qnx-*.cmake`), secpol policies (`target/secpol/`), image snippets, on-target suites (`tests/target/`), and QNX run results in `docs/evidence/` (selftest 31/31 dev + secure, bench, signed dossiers). |
| Build/run instructions: QNX version, target, toolchain | ✅ | [`additional-details.md`](additional-details.md) § Build and run (paste into the Devpost field), from README § Build and run: SDP 8.0, QEMU x86_64 (RPi4 aarch64le cross-built), qcc/gcc 12 + CMake, macOS/Docker and native Linux paths (`docs/setup-macos.md`). 🟡 Add the RPi4 steps after Dec 3. |
| Technology requirement explained: each QNX product, what it does, where to look | ✅ | [`additional-details.md`](additional-details.md) § How the project meets the technology requirement (paste into the Devpost field). |
| Category | ✅ | Automotive & Mobility (select it in the Devpost form). |
| Text description | ✅ | [`devpost.md`](devpost.md), paste-ready. Refresh the numbers after the RPi4 run. |
| Demo video < 3:00, public on YouTube, showing it running **on the device** | 🟡 👤 | The **2:50 QEMU edition** is recorded with male narration and burned-in captions: [`recording-2026-11-21.md`](recording-2026-11-21.md). RPi4 footage/latency remains scheduled for Dec 3; public YouTube upload remains pending. |
| Built during the hackathon | ✅ | Repository history starts Nov 20, 2026; disclosure in `devpost.md`. |
| Pre-existing code disclosed | ✅ | `@decionis/verify` (pre-existing, Apache-2.0), disclosed in `devpost.md`, `README.md` and `THIRD_PARTY.md`. |

## Bonus prizes

| Prize | Status | Evidence / what's left |
|---|---|---|
| Best Use of QNX-specific Technologies | ✅ | secpol typed channels + `--secpol=secure` release image, resource managers, message passing / priority inheritance, pulses, qcrypto, `kx-supervisor`. Summarized in `devpost.md` § How I built it. |
| Best Codelab | ✅ in repo · 👤 public post | [`codelab/README.md`](../../codelab/README.md), verified on QNX by `make codelab` (8/8). Publish it as a public post (dev.to / Hashnode / Medium; your account) and put that URL in the Devpost form. |

## Going public

1. ✅ **Azure Claude key rotated:** confirmed by the owner on Nov 21. The local credentials file was not read or changed for this cleanup.
2. 🟡 **GitHub Support removal ticket created** for PR #34's retained ref and cached sensitive file. The source branch is deleted; GitHub controls its read-only `refs/pull/*` refs. The support bot confirmed ticket creation, not completed removal.
3. ✅ The secrets file is git-ignored on `master` (`.gitignore`). The refreshed local branch/tag history contains no `secrets.platforms.env`; the server's retained PR ref is the remaining cleanup target.
4. ✅ Repo description and 16 topics set (`qnx`, `qnx8`, `secpol`, `software-defined-vehicle`, `ai-safety`, …); README badges (CI, licence, QNX 8.0, secure-image selftest, Node, AAC, hackathon).
5. ✅ Visibility is **public**; About shows *Apache-2.0*.

## Still to do (by date)

| When | Item | Owner |
|---|---|---|
| ✅ Nov 21 | Published **`@decionis/verify` 0.6.1** with Decionis#1752, pinned exactly in `host/verify`, `tests/conformance`, and `spikes/s5-aac`. Conformance passes; the recorded seven-capsule dossier verifies with zero findings. [Publish run](https://github.com/decionis/Decionis/actions/runs/44865404373). **0.6.0 predates #1752.** | Done |
| Dec 3 | **RPi4 bring-up:** QNX 8.0 image, `deploy-rpi`, `make target-selftest` + `kx-bench` on the board; replace the QEMU numbers in README / Devpost / architecture. **Gate:** if the board is not up on Dec 3, the QEMU-only plan applies (no absolute µs claims). | 👤 hardware · Claude |
| Dec 3–8 | Architecture/title SVGs and crisp QEMU gallery captures are complete. RPi4 B-roll remains pending. | 👤 B-roll |
| Dec 9 | **Feature freeze.** After this: bug fixes, docs and video only. | |
| Dec 10 | Cold quickstart dry-run on a clean machine (README host-only path and QEMU path). | 👤 |
| Dec 12 | Update the finished QEMU edit with RPi4 evidence if available; upload public. | 👤 |
| Dec 13 | Final audit against this list; tag `v1.0.0`; re-verify the committed dossiers from the tag. | Claude |
| Dec 14 | **Submit on Devpost.** | 👤 |
| Dec 15 | Buffer for submission blockers only. | |

## Optional (only if time allows before the freeze)

- Rate limiter per actor × action (F12, a *Could* item).
- ✅ WebXR toggle for the 3D twin (*Could*, 3-hour time box): done, view-only, checked in a headset emulator; not yet on a physical headset.
