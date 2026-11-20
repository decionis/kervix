#!/usr/bin/env bash
# Run a command inside the qnx-build container with the QNX SDP 8.0
# environment loaded. Creates the image/container on first use.
#
#   docker/qnx-build.sh                      # interactive shell
#   docker/qnx-build.sh qcc -V               # one-off command
#
# Environment overrides:
#   QNX_SDP_DIR   host path of the SDP (default: ~/qnx800)
#   QNX_LIC_DIR   host path of the QNX license dir (default: ~/.qnx)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="kervix/qnx-build:1"
NAME="kervix-qnx-build"
QNX_SDP_DIR="${QNX_SDP_DIR:-$HOME/qnx800}"
QNX_LIC_DIR="${QNX_LIC_DIR:-$HOME/.qnx}"

die() { echo "qnx-build: $*" >&2; exit 2; }

# `docker info` can hang indefinitely when the daemon is down; bound it (portable, no coreutils).
docker_up() {
  docker info >/dev/null 2>&1 & local pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || { wait "$pid"; return $?; }
    sleep 1
  done
  kill "$pid" 2>/dev/null; return 1
}
docker_up || die "Docker is not running (or not responding). Start Docker Desktop, then retry."
[ -f "$QNX_SDP_DIR/qnxsdp-env.sh" ] || die "QNX SDP not found at $QNX_SDP_DIR (expected qnxsdp-env.sh). See docs/setup-macos.md."
[ -d "$QNX_SDP_DIR/host/linux/x86_64" ] || die "SDP Linux host tools missing in $QNX_SDP_DIR/host/linux/x86_64. Install 'QNX SDP Host Tools (Linux 64-bit)' in QNX Software Center."
[ -d "$QNX_LIC_DIR" ] || die "QNX license dir not found at $QNX_LIC_DIR. Activate your license in QNX Software Center."

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "qnx-build: building image $IMAGE (one-time)…" >&2
  docker build --platform linux/amd64 -t "$IMAGE" "$REPO/docker" >&2
fi

if ! docker container inspect "$NAME" >/dev/null 2>&1; then
  docker create --platform linux/amd64 --name "$NAME" \
    -v "$QNX_SDP_DIR:/opt/qnx800:ro" \
    -v "$QNX_LIC_DIR:/root/.qnx" \
    -v "$REPO:/work" \
    -w /work "$IMAGE" sleep infinity >/dev/null
fi
[ "$(docker container inspect -f '{{.State.Running}}' "$NAME")" = "true" ] || docker start "$NAME" >/dev/null

TTY_FLAGS="-i"; [ -t 0 ] && [ -t 1 ] && TTY_FLAGS="-it"
if [ $# -eq 0 ]; then
  exec docker exec $TTY_FLAGS "$NAME" bash -c 'source /opt/qnx800/qnxsdp-env.sh >/dev/null && exec bash'
fi
# Quote args safely for bash -c
CMD=$(printf '%q ' "$@")
exec docker exec $TTY_FLAGS "$NAME" bash -c "source /opt/qnx800/qnxsdp-env.sh >/dev/null && cd /work && $CMD"
