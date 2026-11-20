# Progress log

One entry per day: done / slipped / cut. Plan: `04-implementation-plan.md`.

| Date | Milestone | Done | Slipped / blocked | Cut |
|---|---|---|---|---|
| Fri 2026-11-20 | M0 | Design approved. Repo scaffold (Apache-2.0, CMake, toolchain files, Docker build container, Makefile, host CI). `catalog/catalog.yaml` + codegen (C header/tables, TS, strict tool schemas). libkxcore host build + catalog tests green. **Spike S5 PASSED** (AAC mapping frozen). | **S0 blocked on you:** myQNX account + license + SDP 8.0 + Linux host tools via Software Center; Docker Desktop not running; RPi4 not yet ordered. | — |
| Fri 2026-11-20 (pm) | M0/S0 | QEMU 11.1.3 installed (you). myQNX account created (you). Headless SDP installer flow written (`docker/install-sdp.sh` → Linux Software Center CLI → volume `kervix-qnx-home`); `qnx-build.sh` uses the volume. | Docker Desktop engine unresponsive (VM stuck idle) and needs a restart. SDP install needs your credentials in your own terminal. | — |
| Fri 2026-11-20 (eve) | M1 (early) | `libkxcore` policy engine: ABI v1 structs, pure `kx_eval` with constitution K1–K4, OR-groups, ABSDIFF, interlock re-check, policy builder/finalizer; `policies/default.yaml` (22 rules) mirrored in C; 150 checks + 200k-case property sweep; clean under ASan/UBSan. | — | — |
