# Developer setup: macOS (Apple Silicon or Intel)

QNX SDP 8.0 ships no macOS host tools, so Kervix uses QNX's documented macOS workflow:
- Install the SDP **and its Linux host tools** with QNX Software Center for macOS.
- Run the Linux tools inside an x86_64 Docker container (`docker/qnx-build.sh`).
- Boot QNX targets in QEMU on the Mac, or on a Raspberry Pi 4.

Everything else (libkxcore tests and the TypeScript host apps) runs natively on macOS.

> On native x86_64 Linux (Ubuntu 22.04/24.04) skip Docker: install the SDP normally, `source ~/qnx800/qnxsdp-env.sh`, and run the same CMake commands directly.

## 1. One-time: QNX account, license, SDP  *(manual — needs your myQNX login)*

1. Create a **myQNX** account and request the free **QNX Everywhere** non-commercial license at <https://qnx.software/en/developers/get-started/qnx-everywhere>.
2. Install **QNX Software Center for macOS hosts** and sign in. The license is activated there.
3. **Add Installation…** → **QNX SDP 8.0**, path **`~/qnx800`**.
4. **Manage Installation → Available**, then add:
   - **QNX SDP Host Tools (Linux 64-bit)**. This is required, because the container uses these tools.
   - For a QEMU target: packages for the x86_64 QEMU image (`mkqnximage` + virtio drivers). Spike S0 records the exact list here.
   - For the RPi4 target: the **Raspberry Pi 4 quick-start target image** for QNX 8.0.
   - For Kervix features: **qcrypto** (+ `openssl-3` provider), **security policy tools** (`secpolcompile`, `secpolgenerate`), **tracelogger** / System Profiler support. S0–S3 record the exact package ids here.
5. Check the result: `ls ~/qnx800/qnxsdp-env.sh ~/qnx800/host/linux/x86_64` lists both paths, and `ls ~/.qnx` shows the license directory.

## 2. One-time: Docker + QEMU

```bash
open -a Docker               # start Docker Desktop (wait for "Engine running")
brew install qemu            # QEMU runs natively on the Mac (TCG emulation for QNX)
docker/qnx-build.sh qcc -V   # first run builds the container image (~2–5 min), then lists compilers
```

The container mounts `~/qnx800` read-only and `~/.qnx` for the license. Override with `QNX_SDP_DIR` / `QNX_LIC_DIR` if yours differ.

## 3. Everyday

```bash
make test        # host: libkxcore unit tests + codegen check + AAC conformance (no SDP needed)
make target      # QNX 8.0 binaries for x86_64 + aarch64le (in the container)
make qnx-shell   # interactive shell with qcc/mkqnximage on PATH
```

## Known caveats

- QEMU on Apple Silicon emulates the CPU (no HVF for QNX guests), so **latency numbers from QEMU are not meaningful**. Benchmarks come from the RPi4.
- Builds in the container run under x86_64 emulation and are slower than native Linux, but fine for a project this size.
- The QNX VS Code Toolkit may warn that `host/darwin/x86_64` is not a directory. QNX's guidance is to ignore it.
