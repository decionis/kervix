# Progress log

One entry per milestone step: done / slipped / cut. Plan: `04-implementation-plan.md`. PR numbers refer to github.com/decionis/kervix.

> Correction (2026-11-20): earlier versions of this log dated some entries "Sat 2026-11-21". All work below happened on **Fri 2026-11-20**, as the PR merge timestamps confirm.

| Date | Milestone | Done (PR) | Slipped / blocked | Cut |
|---|---|---|---|---|
| Fri 2026-11-20 | M0 | Design approved. Repo scaffold, catalog + codegen, host CI. **S5** AAC/COSE mapping proven against `@decionis/verify`. | — | — |
| Fri 2026-11-20 | M0 | Headless SDP install into a Docker volume (macOS M1 host). SDP 8.0 + license (#2). **S0 + S6**: cross-build x86_64/aarch64le, QNX boots in QEMU on the Mac in ~15 s, core tests pass on QNX (#3). | Docker Desktop engine crashed twice; fixed by restart + Resource Saver off | — |
| Fri 2026-11-20 | M0 | **S1 + S2**: kernel-enforced per-path channel typing (`EPERM` even as root), client type from `ctp->info.type_id` (#4). **S3**: qcrypto Ed25519 reproduces the pinned COSE_Sign1 vector; Monocypher fallback dropped (#6). **S4**: boot-time services with per-role secpol type + priority (#7 merged into a stale branch, re-landed as #8). **M0 ✅** | — | — |
| Fri 2026-11-20 | M1 | `libkxcore`: policy engine + constitution K1–K4 (#1); SHA-256/HMAC, JCS, Agent-Safe Intent hashing byte-identical to `@decionis/verify` (#5); grant table (#9). | — | — |
| Fri 2026-11-20 | M1 | `vsimd` 100 Hz simulator + seqlock telemetry + `kxctl` (#10): 16/16 on QNX. | — | — |
| Fri 2026-11-20 | M1 | `kervixd` + `sdv_actuatord` end to end, propose → grant → redeem → actuate (#11): **M1 acceptance 16/16 on QNX**. Found + fixed: reaped grants reported SPENT instead of EXPIRED. | — | — |
| Fri 2026-11-20 | **M1 ✅** | Driver escalation: queue, deferred-reply AWAIT, approve/deny/timeout, re-evaluation on approval (#12): 13/13 on QNX. Found + fixed: an agent blocked in AWAIT could not be interrupted (unblock pulses). | RPi4 not yet ordered: **main schedule risk** (benchmarks + on-device video) | — |

## Schedule status (end of Fri 2026-11-20)

- Plan: M0 by Sun 11-22, M1 by Fri 11-27. **Actual: M0 and M1 both complete on Fri 11-20, about 7 days ahead.**
- Next: M2. The signed AAC capsule ledger (Ed25519 via qcrypto, crash-safe append-only file, epoch capsules), `kervix-verify` on top of `@decionis/verify`, then the `--secpol=secure` image with every Kervix channel typed.
- The buffer gained should go into M3 polish (3D dashboard, live Claude agent) and RPi4 benchmarking once the hardware arrives.
