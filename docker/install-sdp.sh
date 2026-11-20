#!/usr/bin/env bash
# One-time, headless install of QNX SDP 8.0 into a Docker named volume, using
# the QNX Software Center *Linux* installer inside an x86_64 container.
# Works on macOS (incl. Apple Silicon) and Linux.
#
#   docker/install-sdp.sh ~/Downloads/qnx-setup-2.0.4-202501021438-linux.run
#
# You are prompted (inside the container) for your myQNX email, password and
# license key. They are never written to disk, shell history, `docker inspect`
# or logs. Run this in your own terminal: it needs an interactive TTY.
#
# Why a named volume and not ~/qnx800 on the Mac: macOS filesystems are
# case-insensitive (Linux SDP paths can collide), and volume I/O is much
# faster than bind mounts for the thousands of headers the compiler reads.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="kervix/qnx-build:1"
VOLUME="${KX_QNX_VOLUME:-kervix-qnx-home}"
RUN_FILE="${1:-}"

die() { echo "install-sdp: $*" >&2; exit 2; }
[ -n "$RUN_FILE" ] || die "usage: $0 <path to qnx-setup-*-linux.run>"
[ -f "$RUN_FILE" ] || die "installer not found: $RUN_FILE"
[ -t 0 ] || die "needs an interactive terminal (credentials are prompted inside the container)"
RUN_DIR="$(cd "$(dirname "$RUN_FILE")" && pwd)"
RUN_BASE="$(basename "$RUN_FILE")"

# shellcheck source=docker/lib.sh
source "$REPO/docker/lib.sh"
kx_docker_up || die "Docker is not running (or not responding). Start/restart Docker Desktop, then retry."
kx_ensure_image "$IMAGE" "$REPO/docker"
docker volume inspect "$VOLUME" >/dev/null 2>&1 || docker volume create "$VOLUME" >/dev/null

# Isolation: the installer directory is mounted read-only in its own path;
# the in-container script comes from the repo; nothing else is shared.
exec docker run --rm -it --platform linux/amd64 \
  -v "$VOLUME:/root" \
  -v "$RUN_DIR:/inst:ro" \
  -v "$REPO/docker/sdp-install.container.sh:/kx/sdp-install.sh:ro" \
  -e QSC_RUN="/inst/$RUN_BASE" \
  "$IMAGE" bash /kx/sdp-install.sh
