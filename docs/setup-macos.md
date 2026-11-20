# Developer setup: macOS (Apple Silicon or Intel)

QNX SDP 8.0 ships no macOS host tools, so Kervix uses QNX's documented macOS workflow:
- Run the SDP's Linux host tools inside an x86_64 Docker container (`docker/qnx-build.sh`).
- Boot QNX targets in QEMU on the Mac, or on a Raspberry Pi 4.

Everything else (libkxcore tests and the TypeScript host apps) runs natively on macOS.

The SDP is installed headlessly with the Software Center **Linux** command-line tool inside the container. No macOS Software Center is needed.

> On native x86_64 Linux (Ubuntu 22.04/24.04) skip Docker: install the SDP normally, `source ~/qnx800/qnxsdp-env.sh`, and run the same CMake commands directly.

## 1. One-time: QNX account and license  *(manual)*

1. Create a **myQNX** account.
2. Request the free **QNX Everywhere** non-commercial license at <https://qnx.software/en/developers/get-started/qnx-everywhere>.
3. Copy the **license key** from myQNX → *License Keys*. It is shown as `XXXX-XXXX-XXXX-XXXX-XXXX`.
4. Download **QNX Software Center for Linux hosts** (`qnx-setup-<ver>-linux.run`). You do **not** need the macOS Software Center.

## 2. One-time: Docker, QEMU, SDP

```bash
open -a Docker      # Docker Desktop must show "Engine running"
brew install qemu   # QEMU runs natively on the Mac (TCG emulation for QNX guests)

# Install SDP 8.0 headlessly into the Docker volume "kervix-qnx-home".
# Run this in YOUR terminal: it prompts for myQNX email, password and key inside the container.
docker/install-sdp.sh ~/Downloads/qnx-setup-2.0.4-202501021438-linux.run

docker/qnx-build.sh qcc -V   # should list the gcc_ntox86_64 / gcc_ntoaarch64le variants
```

Deployment in the myQNX dashboard assigns the license to your account; the
Software Center must also activate it in the build environment. The installer
activates the supplied key before installing SDP. If you leave the key blank,
it synchronizes your deployed licenses and selects the key only when there is
exactly one; otherwise it asks for your specific SDP 8.0 key. Password and key
entry is hidden, and license keys are masked in the installer output. myQNX
authentication uses a temporary options file in container RAM, removed on exit,
because QNX Software Center logs passwords passed directly on the command line.

Keep the `kervix-qnx-home` volume when rebuilding containers: it retains
`/root/.qnx` license activation data as well as the SDK. See QNX's
[command-line licensing instructions](https://www.qnx.com/developers/docs/qsc/com.qnx.doc.qsc.user_guide/topic/commandline_qsc.html).

Why a Docker volume instead of `~/qnx800` on the Mac:
- macOS file systems are case-insensitive, and Linux SDP paths can collide.
- Volume I/O is much faster for compiler header lookups.

On **native x86_64 Linux** you can instead install the SDP normally and run `QNX_SDP_DIR=~/qnx800 docker/qnx-build.sh …`, or skip Docker entirely.

The baseline already includes everything needed so far: qcc 12.2 for x86_64 and aarch64le, `mkqnximage`, `secpolcompile`, `traceprinter`, and the qcrypto and secpol headers and libs. The RPi4 target image is added when the hardware arrives.

## 3. Everyday

```bash
make test        # host: libkxcore unit tests + codegen check + AAC conformance (no SDP needed)
make target      # QNX 8.0 binaries for x86_64 + aarch64le (in the container)
make qnx-shell   # interactive shell with qcc/mkqnximage on PATH

make qemu-image  # build the QNX 8.0 x86_64 QEMU image (vm/qemu-x86_64, git-ignored)
make qemu-start  # boot headless (~15 s on an M1); console in vm/qemu-x86_64/console.log
make qemu-ssh    # root shell on the target (project-local key in vm/ssh/)
make target-test # cross-build + run the libkxcore tests ON QNX
make qemu-stop
```

## Known caveats

- QEMU on Apple Silicon emulates the CPU (no HVF for QNX guests), so **latency numbers from QEMU are not meaningful**. Benchmarks come from the RPi4.
- Builds in the container run under x86_64 emulation and are slower than native Linux, but fine for a project this size.
- The QNX VS Code Toolkit may warn that `host/darwin/x86_64` is not a directory. QNX's guidance is to ignore it.
