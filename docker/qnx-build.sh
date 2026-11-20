#!/usr/bin/env bash
# Run a command inside the qnx-build container with the QNX SDP 8.0
# environment loaded. Creates the image/container on first use.
#
#   docker/qnx-build.sh                      # interactive shell
#   docker/qnx-build.sh qcc -V               # one-off command
#
# SDP location (pick one):
#   default        Docker volume "kervix-qnx-home" mounted at /root, filled by
#                  docker/install-sdp.sh (recommended on macOS)
#   QNX_SDP_DIR=…  bind-mount an existing SDP install (e.g. native Linux ~/qnx800);
#                  QNX_LIC_DIR (default ~/.qnx) is mounted for the license
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="kervix/qnx-build:1"
VOLUME="${KX_QNX_VOLUME:-kervix-qnx-home}"

die() { echo "qnx-build: $*" >&2; exit 2; }
# shellcheck source=docker/lib.sh
source "$REPO/docker/lib.sh"

kx_docker_up || die "Docker is not running (or not responding). Start/restart Docker Desktop, then retry."
kx_ensure_image "$IMAGE" "$REPO/docker"

if [ -n "${QNX_SDP_DIR:-}" ]; then
  QNX_LIC_DIR="${QNX_LIC_DIR:-$HOME/.qnx}"
  [ -f "$QNX_SDP_DIR/qnxsdp-env.sh" ] || die "no qnxsdp-env.sh in QNX_SDP_DIR=$QNX_SDP_DIR"
  MOUNTS=(-v "$QNX_SDP_DIR:/root/qnx800:ro" -v "$QNX_LIC_DIR:/root/.qnx")
  NAME="kervix-qnx-build-bind"
else
  docker volume inspect "$VOLUME" >/dev/null 2>&1 \
    || die "SDP volume '$VOLUME' not found. Install the SDP first: docker/install-sdp.sh <qnx-setup-*-linux.run>  (see docs/setup-macos.md)"
  MOUNTS=(-v "$VOLUME:/root")
  NAME="kervix-qnx-build"
fi

if ! docker container inspect "$NAME" >/dev/null 2>&1; then
  docker create --platform linux/amd64 --name "$NAME" "${MOUNTS[@]}" \
    -v "$REPO:/work" -w /work "$IMAGE" sleep infinity >/dev/null
fi
[ "$(docker container inspect -f '{{.State.Running}}' "$NAME")" = "true" ] || docker start "$NAME" >/dev/null

docker exec "$NAME" test -f /root/qnx800/qnxsdp-env.sh \
  || die "SDP not installed in the container (/root/qnx800/qnxsdp-env.sh missing). Run docker/install-sdp.sh first."

ENV_CMD='source /root/qnx800/qnxsdp-env.sh >/dev/null'
TTY_FLAGS="-i"; [ -t 0 ] && [ -t 1 ] && TTY_FLAGS="-it"
if [ $# -eq 0 ]; then
  exec docker exec $TTY_FLAGS "$NAME" bash -c "$ENV_CMD && exec bash"
fi
CMD=$(printf '%q ' "$@")
exec docker exec $TTY_FLAGS "$NAME" bash -c "$ENV_CMD && cd /work && $CMD"
