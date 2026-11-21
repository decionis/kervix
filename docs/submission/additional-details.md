# Devpost submission: additional details

> Paste-ready answers for the two extra Devpost fields. Repository: <https://github.com/decionis/kervix> (Apache-2.0).
> Links point at `master`. QEMU numbers are emulated; Raspberry Pi 4 runs are scheduled from Dec 3 and are not claimed here until they exist.

---

## Build and run instructions

### What it runs on

| | |
|---|---|
| **QNX version** | **QNX SDP 8.0** (QNX OS 8.0.0; `uname -a` on the target: `QNX kervix-qemu 8.0.0 … x86pc x86_64`). Installed with the QNX Software Center 2.0.4 installer under the free **QNX Everywhere** non-commercial licence. |
| **Target** | **QEMU, x86_64**: an image built by `mkqnximage --type=qemu` (2 vCPU, 1 GB RAM), booted with `scripts/qemu.sh`. All on-target results in the repository come from this target. The **Raspberry Pi 4 (aarch64le)** binaries are cross-built on every build; runs on the board are scheduled once it arrives (Dec 3). |
| **Toolchain** | **`qcc` / `q++` from SDP 8.0 (gcc 12.2.0)**, variants `gcc_ntox86_64` and `gcc_ntoaarch64le`, driven by CMake + Ninja through the toolchain files [`cmake/qnx-common.cmake`](https://github.com/decionis/kervix/blob/master/cmake/qnx-common.cmake), [`cmake/qnx-x86_64.cmake`](https://github.com/decionis/kervix/blob/master/cmake/qnx-x86_64.cmake) and [`cmake/qnx-aarch64le.cmake`](https://github.com/decionis/kervix/blob/master/cmake/qnx-aarch64le.cmake). C11 throughout. |
| **Development host** | Apple-silicon Mac (macOS). The SDP's Linux host tools run in an x86_64 Docker container ([`docker/qnx-build.sh`](https://github.com/decionis/kervix/blob/master/docker/qnx-build.sh)); QEMU 11 runs the image with TCG emulation. On native x86_64 Linux, source `qnxsdp-env.sh` and run the same `make` targets. |
| **Host side** | Node ≥ 22.18 (TypeScript via type stripping), a C11 compiler and CMake ≥ 3.20 for the host build of the portable core, Docker (macOS), QEMU. |

### 1. Without QNX: verify a ledger that was signed on QNX

```bash
git clone https://github.com/decionis/kervix && cd kervix
npm ci
make test                      # C core + unit tests (host build), codegen check, TypeScript tests, AAC/COSE conformance
node host/verify/kervix-verify.mjs tests/fixtures/dossier-qnx-qemu-2026-11-20
```

Expected last line: `VERIFIED`. The verifier checks the signatures and the hash chain, then re-runs every decision through the vehicle's own C policy core compiled to WebAssembly.

### 2. One-time QNX SDP 8.0 setup

Follow [`docs/setup-macos.md`](https://github.com/decionis/kervix/blob/master/docs/setup-macos.md):
1. Create a myQNX account and get a QNX Everywhere licence key.
2. Install SDP 8.0 into the build container with `docker/install-sdp.sh <qnx-setup-….run>`.
3. Check with `docker/qnx-build.sh qcc -V`, which should list `12.2.0,gcc_ntox86_64` and `12.2.0,gcc_ntoaarch64le`.

On native Linux, set `QNX_SDP_DIR=~/qnx800` to bind-mount an existing install.

### 3. Build for QNX and run every check on the target

```bash
make target                    # cross-build every component for x86_64 and aarch64le (qcc via CMake)
make target-selftest           # build a QNX 8.0 image (mkqnximage, --secpol=open), boot it in QEMU,
                               # run kx-selftest on the target, verify the run's signed ledger on the host
make target-selftest-secure    # the same on the --secpol=secure release image
make codelab                   # the secpol codelab, every step executed and checked on QNX
make help                      # every other on-target suite: m1, escalation, ledger, secpol, supervisor,
                               # kxgw, bridge, agent, policy, bench
```

`make target-selftest` ends with `SELFTEST RESULT: PASS`, followed by the host-side `VERIFIED` of the dossier exported from the target. Reference outputs: [dev image](https://github.com/decionis/kervix/blob/master/docs/evidence/selftest-qnx-qemu-open.txt), [secure image](https://github.com/decionis/kervix/blob/master/docs/evidence/selftest-qnx-qemu-secure.txt), [benchmark](https://github.com/decionis/kervix/blob/master/docs/evidence/bench-qnx-qemu.txt).

To work on the running target: `scripts/qemu.sh ssh` gives you a QNX shell; `pidin -f an_` lists the Kervix processes with their security types.

### 4. The demo (dashboard + agent against the QNX target)

```bash
make target-agent              # boots the gateway image and leaves it running
npm run dashboard              # build the dashboard once
npm run bridge                 # http://127.0.0.1:8787 : the dashboard, bridged to the four QNX gateways
npm run agent -- script scenarios/s1-cold.json scenarios/s2-injection.json scenarios/s3-escalate.json
npm run agent -- live-demo     # optional: live Claude (needs ANTHROPIC_API_KEY, or Foundry credentials)
```

The scripted agent replays recorded *words* only: every verdict is decided live by `kervixd` on QNX. No API key is needed.

---

## How the project meets the technology requirement

**Kervix runs on QNX 8.0.** The execution authority, the vehicle simulator, the actuator gateway, the network gateways, the supervisor and the on-target test tools are C programs built with the SDP 8.0 toolchain. They run as QNX resource managers and clients in an image built with `mkqnximage`, under a QNX security policy, in QEMU. The host side (dashboard, bridge, agent, verifier) only talks to the target over TCP, through gateways that themselves run on QNX.

Each QNX product or technology below is listed with what it does in Kervix and where a reviewer can see it.

### QNX SDP 8.0, QNX Everywhere licence, QNX Software Center
- **What:** the target OS, headers, libraries and host tools, installed with the Software Center installer under the QNX Everywhere licence.
- **Where:**
  - [`docker/install-sdp.sh`](https://github.com/decionis/kervix/blob/master/docker/install-sdp.sh) and [`docs/setup-macos.md`](https://github.com/decionis/kervix/blob/master/docs/setup-macos.md) for the install.
  - The first line of every [selftest table](https://github.com/decionis/kervix/blob/master/docs/evidence/selftest-qnx-qemu-secure.txt): `Kervix on QNX kervix-qemu 8.0.0`.

### qcc / q++ (gcc 12.2.0)
- **What:** cross-compiles every target component for `x86_64` and `aarch64le`.
- **Where:**
  - [`cmake/qnx-common.cmake`](https://github.com/decionis/kervix/blob/master/cmake/qnx-common.cmake) sets `CMAKE_C_COMPILER` to `${QNX_HOST}/usr/bin/qcc` and `CMAKE_SYSTEM_NAME QNX`.
  - `make target` builds both architectures.

### mkqnximage (and the mkifs it drives)
- **What:** builds the bootable QEMU image. Kervix's binaries, policy and boot commands go in through mkqnximage snippets. The same tool produces the development image (`--secpol=open`) and the release image (`--secpol=secure --policy=…`).
- **Where:**
  - [`scripts/qemu.sh`](https://github.com/decionis/kervix/blob/master/scripts/qemu.sh) (`image`).
  - [`target/image/snippets/system_files.custom`](https://github.com/decionis/kervix/blob/master/target/image/snippets/system_files.custom).
  - [`target/image/snippets/post_start.custom`](https://github.com/decionis/kervix/blob/master/target/image/snippets/post_start.custom), which starts every service under its own security type, uid and priority.

### QNX Neutrino resource managers
- **What:** the execution authority **`kervixd`** is a resource manager with **one dispatch channel per trust level**: agent, actuator, driver HMI, observer and workshop admin. It serves `/dev/kervix/{intent,redeem,escalations,stats,policy,dossier}`. `vsimd` (`/dev/sdv/telemetry`, `/dev/sdv/sim/*`) and `sdv_actuatord` (`/dev/sdv/actuators`, plus the deliberately unreachable `/dev/sdv/actuators/raw`) are resource managers too.
- **Where:** [`target/kervixd/kervixd.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kervixd.c):
  - `main()` creates one `dispatch_t` per channel and attaches each node with `secpol_resmgr_attach()`.
  - `io_devctl()` handles PROPOSE, REDEEM, AWAIT, RESOLVE, POLICY_* and DOSSIER_*.
  - `io_read()` serves `/dev/kervix/stats`.
- **On the target:** `cat /dev/kervix/stats`; `ls /dev/kervix`.

### Neutrino message passing (synchronous send/receive/reply, priority inheritance)
- **What:**
  - Every agent proposal is a synchronous `devctl()` message to `kervixd`. The decision is computed and recorded before `MsgReply`.
  - The driver-HMI gateway runs at priority 30 and the agent gateway at 10, so the kernel's priority inheritance keeps the driver's channel responsive under an agent flood.
- **Where:**
  - `propose()` in [`kervixd.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kervixd.c). The caller's identity comes from the kernel-stamped `ctp->info.type_id` / `ctp->info.pid`, never from the message payload.
  - Priorities: `on -p 30` / `on -p 10` in [`post_start.custom`](https://github.com/decionis/kervix/blob/master/target/image/snippets/post_start.custom).
  - Measurement: [`target/kx-bench/kx_bench.c`](https://github.com/decionis/kervix/blob/master/target/kx-bench/kx_bench.c) section 3. Result: HMI p99 under a 16.6k proposals/s flood is **1.03×** idle, emulated ([`bench-qnx-qemu.txt`](https://github.com/decionis/kervix/blob/master/docs/evidence/bench-qnx-qemu.txt)).

### Deferred replies and unblock handling
- **What:** an agent waiting for the driver's approval stays **REPLY-blocked in the kernel**, with no polling. `kervixd` keeps the `rcvid` and replies when the driver decides or the timeout fires. If the waiting client is killed, the unblock pulse releases it.
- **Where:** in [`kervixd.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kervixd.c):
  - `io_devctl()` case `KX_DCMD_AWAIT` stores `e->waiter = ctp->rcvid` and returns `_RESMGR_NOREPLY`.
  - `io_unblock()` handles the unblock.
  - `MsgReplyv()` with a local `iov_t[2]` serves the ledger records.

### Pulses and registered events
- **What:** a new escalation is pushed to the driver HMI as a pulse, not polled. The HMI gateway registers a `SIGEV_PULSE` with `MsgRegisterEvent()`, and `kervixd` delivers it with `MsgDeliverEvent()`.
- **Where:**
  - `esc_subscribe()` in [`target/kxgw/kxgw.c`](https://github.com/decionis/kervix/blob/master/target/kxgw/kxgw.c) (`SIGEV_PULSE_INIT` + `MsgRegisterEvent`).
  - `ring_hmi()` in [`kervixd.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kervixd.c).
  - `cmd_telemetry_watch()` in [`target/kxctl/kxctl.c`](https://github.com/decionis/kervix/blob/master/target/kxctl/kxctl.c) uses the same mechanism for telemetry updates from `vsimd`.

### QNX security policies (secpol): the core of the design
- **What:** the kernel enforces the trust topology. In the policy:
  - Each `kervixd` channel has its own **channel type**.
  - **`channel connect` rules** say which process type may reach which channel. The agent's type can propose, but it can never connect to the actuator, approve its own request, write vehicle state or reach the raw actuator path. The kernel refuses with `EPERM` **even for root**.
  - Daemons drop privileges one way with `derive_type` + `settypeid`.
  - The **release image runs `--secpol=secure`**: one complete policy, nothing runs untyped, and the root shell is confined.
- **Where:**
  - [`target/secpol/kervix.secpol`](https://github.com/decionis/kervix/blob/master/target/secpol/kervix.secpol): `allow_attach … <channel type>`, `allow … :channel connect`, `derive_type`.
  - [`target/secpol/system.secpol`](https://github.com/decionis/kervix/blob/master/target/secpol/system.secpol), the reviewed harvest produced by [`scripts/secpol-harvest.sh`](https://github.com/decionis/kervix/blob/master/scripts/secpol-harvest.sh).
  - Code:
    - `secpol_resmgr_attach()` and `secpol_transition_type()` in `kervixd.c`;
    - `secpol_posix_spawnattr_settypeid()` in [`target/kx-supervisor`](https://github.com/decionis/kervix/tree/master/target/kx-supervisor);
    - `on -T <type>` in the boot snippet.
- **On the target and in the demo:**
  - `kx-rogue`, run as the deployed agent type, reports **10/10 attacks refused by the kernel, 0 open** (selftest J4; [`target/kx-rogue`](https://github.com/decionis/kervix/tree/master/target/kx-rogue); video shot 6).
  - Selftest check "no secpol refusals for any legitimate role" shows the policy is exact both ways.

### secpolgenerate
- **What:** used two ways.
  - **Harvest:** it records what the stock system needs, which becomes the reviewed `system.secpol`.
  - **Monitor mode on the release image:** its refusal log `/dev/secpolgenerate/errors` is how the selftest proves zero unexpected denials system-wide.
- **Where:** [`target/secpol/monitor.secpol`](https://github.com/decionis/kervix/blob/master/target/secpol/monitor.secpol), the `OPT_SECPOL_secure` branch of `post_start.custom`, and `check_denials()` in [`target/kx-selftest/kx_selftest.c`](https://github.com/decionis/kervix/blob/master/target/kx-selftest/kx_selftest.c).

### Process-manager abilities
- **What:**
  - Non-root socket users need the `network/jailroot` ability. The four gateways get it, and nothing else does.
  - Squatting a path is refused by the `pathspace` ability (`EPERM`), which the codelab demonstrates.
- **Where:** `ability network/jailroot` in [`kervix.secpol`](https://github.com/decionis/kervix/blob/master/target/secpol/kervix.secpol); [`codelab/README.md`](https://github.com/decionis/kervix/blob/master/codelab/README.md).

### qcrypto
- **What:**
  - **Ed25519** (`eddsa-pure`) signs every ledger capsule as a COSE_Sign1 envelope.
  - **Ed25519 verify** checks the author and approver signatures on a policy update before activation.
  - **`drbg-ctr-256`** generates grant ids, the per-boot grant key and the epoch id.
- **Where:**
  - `sign_envelope()`, called by the `writer()` thread, in [`target/kervixd/kxledger.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kxledger.c) (`qcrypto_signature_sign_oneshot`).
  - `qc_verify()` in [`kervixd.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kervixd.c) (`qcrypto_signature_verify_oneshot`).
  - `qcrypto_rng_request("drbg-ctr-256", …)` in `kervixd.c` `main()`.
- **Output:** every dossier exported from the target verifies offline with the vehicle key (`✔ signatures` in `kervix-verify`).

### POSIX shared memory on QNX
- **What:** the 100 Hz simulator publishes vehicle state through a single-writer seqlock in shared memory. `kervixd` maps it **read-only**, so nothing but the simulator can change what the authority sees.
- **Where:**
  - `shm_open` / `mmap(PROT_READ)` in [`kervixd.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kervixd.c).
  - `shm_open(O_RDWR | O_CREAT)` in [`target/vsimd/vsimd.c`](https://github.com/decionis/kervix/blob/master/target/vsimd/vsimd.c).
  - [`target/include/kervix/seqlock.h`](https://github.com/decionis/kervix/blob/master/target/include/kervix/seqlock.h).

### io-sock (TCP networking)
- **What:** the four `kxgw` gateways (agent 7301, HMI 7302, observer 7303, world 7304) are the only network-facing processes. Each runs under its own type, uid and priority, and translates JSON lines into messages to `kervixd`.
- **Where:** [`target/kxgw/kxgw.c`](https://github.com/decionis/kervix/blob/master/target/kxgw/kxgw.c), [`target/kxgw/wire.c`](https://github.com/decionis/kervix/blob/master/target/kxgw/wire.c) (fuzzed in CI).

### QNX timing: ClockCycles() and the system page
- **What:** in-server decision latency and the benchmark's round-trip times use `ClockCycles()` with `SYSPAGE_ENTRY(qtime)->cycles_per_sec`.
- **Where:** `propose()` in `kervixd.c`; [`kx_bench.c`](https://github.com/decionis/kervix/blob/master/target/kx-bench/kx_bench.c).
- **Output:** the PROPOSE latency histogram in `/dev/kervix/stats` and on the dashboard. On QEMU it reads p50 39 µs / p99 167 µs and is labelled emulated.

### QNX OS utilities used by the tests and the demo
- **What and where:**
  - `on -T <type> -u <uid> -p <prio>` starts each role exactly as deployed.
  - `pidin` shows the processes and their types.
  - `slay -9 kervixd` is the fail-closed crash test (selftest J5; video shot 7).
  - `slog2info` reads the kernel's refusal log.
  - `waitfor` sequences the boot.
- All of these appear in [`tests/target/`](https://github.com/decionis/kervix/tree/master/tests/target) and [`kx_selftest.c`](https://github.com/decionis/kervix/blob/master/target/kx-selftest/kx_selftest.c).

### QEMU (the SDP's QEMU image type)
- **What:** the run target for every result in the repository.
- **Where:** `mkqnximage --type=qemu` in [`scripts/qemu.sh`](https://github.com/decionis/kervix/blob/master/scripts/qemu.sh).

### Where to look first (5 minutes)

1. [`target/secpol/kervix.secpol`](https://github.com/decionis/kervix/blob/master/target/secpol/kervix.secpol): the trust topology the kernel enforces.
2. `propose()` and `io_devctl()` in [`target/kervixd/kervixd.c`](https://github.com/decionis/kervix/blob/master/target/kervixd/kervixd.c): the resource manager and the decision path.
3. [`docs/evidence/selftest-qnx-qemu-secure.txt`](https://github.com/decionis/kervix/blob/master/docs/evidence/selftest-qnx-qemu-secure.txt): every claim checked on QNX, on the secure release image.
4. Video, shot 6: `kx-rogue` as the agent, every attack refused by the kernel. Shot 9: the selftest on the target.
5. [`codelab/README.md`](https://github.com/decionis/kervix/blob/master/codelab/README.md): the same QNX techniques in a 120-line resource manager, step by step.

### Not used

QNX Momentics IDE, the QNX VS Code extension, the QNX Sensor Framework, the DDK, QNX Ports and QNX Hypervisor are **not used**. The build is CMake + `qcc` on the command line. The hypervisor is listed under "What's next" in the main description.
