# Submission checklist (QNX Global Hackathon 2026, Devpost)

> Deadline **Tue Dec 15, 14:00 ET**. Plan: feature freeze Wed Dec 9, submit **Mon Dec 14** (`04-implementation-plan.md`).
> Status as of **Sat Nov 21**. ✅ done · 🟡 in progress / scheduled · 👤 owner action (needs your accounts or hardware) · ⛔ blocker

## Required by the rules

| Requirement | Status | Evidence / what's left |
|---|---|---|
| Public GitHub repository | ✅ | `decionis/kervix` is public (Nov 21). See "Going public" below for the key rotation. |
| Open-source licence visible in the repo's About section | ✅ | `LICENSE` is the canonical Apache-2.0 text; GitHub detects it as `Apache-2.0`. |
| Really builds for / runs on QNX 8.0 | ✅ | CMake toolchains (`cmake/qnx-*.cmake`), secpol policies (`target/secpol/`), image snippets, on-target suites (`tests/target/`), and QNX run results in `docs/evidence/` (selftest 29/29 dev + secure, bench, signed dossiers). |
| Build/run instructions: QNX version, target, toolchain | ✅ | [`additional-details.md`](additional-details.md) § Build and run (paste into the Devpost field), from README § Build and run: SDP 8.0, QEMU x86_64 (RPi4 aarch64le cross-built), qcc/gcc 12 + CMake, macOS/Docker and native Linux paths (`docs/setup-macos.md`). 🟡 Add the RPi4 steps after Dec 3. |
| Technology requirement explained: each QNX product, what it does, where to look | ✅ | [`additional-details.md`](additional-details.md) § How the project meets the technology requirement (paste into the Devpost field). |
| Category | ✅ | Automotive & Mobility (select it in the Devpost form). |
| Text description | ✅ | [`devpost.md`](devpost.md), paste-ready. Refresh the numbers after the RPi4 run. |
| Demo video < 3:00, public on YouTube, showing it running **on the device** | 🟡 👤 | Shot list: [`video-shot-list.md`](video-shot-list.md). Record from Dec 3 (RPi4); edit to ≤ 2:59 by Dec 12; upload **public**. |
| Built during the hackathon | ✅ | Repository history starts Nov 20, 2026; disclosure in `devpost.md`. |
| Pre-existing code disclosed | ✅ | `@decionis/verify` (pre-existing, Apache-2.0), disclosed in `devpost.md`, `README.md` and `THIRD_PARTY.md`. |

## Bonus prizes

| Prize | Status | Evidence / what's left |
|---|---|---|
| Best Use of QNX-specific Technologies | ✅ | secpol typed channels + `--secpol=secure` release image, resource managers, message passing / priority inheritance, pulses, qcrypto, `kx-supervisor`. Summarized in `devpost.md` § How I built it. |
| Best Codelab | ✅ in repo · 👤 public post | [`codelab/README.md`](../../codelab/README.md), verified on QNX by `make codelab` (8/8). Publish it as a public post (dev.to / Hashnode / Medium; your account) and put that URL in the Devpost form. |

## Going public

1. 👤 **Rotate the Azure Claude key** that was pushed to closed PR #34 on Nov 21, and update your local `secrets.platforms.env`.
2. 👤 Optionally ask **GitHub Support** to purge PR #34's refs. With the key rotated, what remains there is a dead credential.
3. ✅ The secrets file is git-ignored on `master` (`.gitignore`). No branch or tag contains it: a history scan of all refs finds 0 occurrences.
4. ✅ Repo description and 16 topics set (`qnx`, `qnx8`, `secpol`, `software-defined-vehicle`, `ai-safety`, …); README badges (CI, licence, QNX 8.0, secure-image selftest, Node, AAC, hackathon).
5. ✅ Visibility is **public**; About shows *Apache-2.0*.

## Still to do (by date)

| When | Item | Owner |
|---|---|---|
| when ready | Publish the next `@decionis/verify` release containing decionis/Decionis#1752. **0.6.0 does not include it**: it was published 4 minutes before #1752 merged. Then pin it in Kervix (`host/verify`, `tests/conformance`, `spikes/s5-aac`); the `follows` / `vehicle.*` info findings disappear. | 👤 publish · Claude pins |
| Dec 3 | **RPi4 bring-up:** QNX 8.0 image, `deploy-rpi`, `make target-selftest` + `kx-bench` on the board; replace the QEMU numbers in README / Devpost / architecture. **Gate:** if the board is not up on Dec 3, the QEMU-only plan applies (no absolute µs claims). | 👤 hardware · Claude |
| Dec 3–8 | Video assets: `docs/images/architecture.svg`, title card, RPi4 B-roll. | Claude (svg) · 👤 B-roll |
| Dec 9 | **Feature freeze.** After this: bug fixes, docs and video only. | |
| Dec 10 | Cold quickstart dry-run on a clean machine (README host-only path and QEMU path). | 👤 |
| Dec 12 | Record and edit the video; upload public. | 👤 |
| Dec 13 | Final audit against this list; tag `v1.0.0`; re-verify the committed dossiers from the tag. | Claude |
| Dec 14 | **Submit on Devpost.** | 👤 |
| Dec 15 | Buffer for submission blockers only. | |

## Optional (only if time allows before the freeze)

- Rate limiter per actor × action (F12, a *Could* item).
- WebXR toggle for the 3D twin (*Could*, 3-hour time box).
