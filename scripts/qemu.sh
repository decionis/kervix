#!/usr/bin/env bash
# Boot / manage the QNX 8.0 QEMU image natively on the host (macOS or Linux).
# Mirrors mkqnximage's qemu/runimage, but uses QEMU user-mode networking with
# port forwards (no bridge/tap needed, works on macOS):
#   localhost:2222 -> target:22 (ssh)
#   localhost:7301..7304 -> target kxgw roles (agent, hmi, observer, world)
#
#   scripts/qemu.sh image     # build/refresh the image (in the qnx-build container)
#                             # env: KX_MKQNXIMAGE_EXTRA=<opts>, KX_SNIPPETS=<dir of *.custom>
#   scripts/qemu.sh start     # boot headless; console -> vm/qemu-x86_64/console.log
#   scripts/qemu.sh wait      # block until ssh answers (prints boot time)
#   scripts/qemu.sh ssh [cmd] # ssh as root with the project dev key
#   scripts/qemu.sh scp <src...> <dst>   # copy to target (dst is a target path)
#   scripts/qemu.sh stop | status | console
#
# On Apple Silicon this is TCG emulation: functional, never use for timing.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${KX_QEMU_ARCH:-x86_64}"
VM="$REPO/vm/qemu-$ARCH"
OUT="$VM/output"
KEY="$REPO/vm/ssh/kervix_ed25519"
SSH_PORT="${KX_SSH_PORT:-2222}"
PIDFILE="$VM/qemu.pid"
LOG="$VM/console.log"
SSH_OPTS=(-i "$KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes)

die() { echo "qemu.sh: $*" >&2; exit 2; }
running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

cmd_image() {
  mkdir -p "$VM" "$REPO/vm/ssh"
  [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C kervix-dev -f "$KEY"
  # KX_SNIPPETS=<dir>: install *.custom mkqnximage snippets (files + boot commands);
  # without it, reset any previously installed snippets to empty placeholders
  mkdir -p "$VM/local/snippets"
  for f in system_files ifs_files data_files ifs_start post_start profile; do
    if [ -n "${KX_SNIPPETS:-}" ] && [ -f "$KX_SNIPPETS/$f.custom" ]; then
      cp "$KX_SNIPPETS/$f.custom" "$VM/local/snippets/$f.custom"
    else
      echo "# local/snippets/$f.custom (managed by scripts/qemu.sh)" > "$VM/local/snippets/$f.custom"
    fi
  done
  # mkqnximage REMEMBERS options between builds: a "plain" build after a secure
  # one stays secure. State every security option; KX_MKQNXIMAGE_EXTRA overrides.
  "$REPO/docker/qnx-build.sh" bash -c "cd /work/vm/qemu-$ARCH && mkqnximage --noprompt --type=qemu \
    --arch=$ARCH --hostname=kervix-qemu --ip=dhcp --ssh-ident=/work/vm/ssh/kervix_ed25519.pub \
    --data-size=256 --cpu=2 --ram=1G --secpol=no --policy=none --secure-procfs=no \
    --build ${KX_MKQNXIMAGE_EXTRA:-}"
}

cmd_start() {
  running && { echo "already running (pid $(cat "$PIDFILE"))"; return 0; }
  [ -f "$OUT/ifs.bin" ] && [ -f "$OUT/disk-qemu.vmdk" ] || die "no image in $OUT; run: scripts/qemu.sh image"
  [ "$ARCH" = x86_64 ] || die "only x86_64 is wired up (aarch64 virt needs extra BSP packages)"
  local fwd="hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22"
  for p in 7301 7302 7303 7304; do fwd+=",hostfwd=tcp:127.0.0.1:${p}-:${p}"; done
  : > "$LOG"
  ( cd "$VM" && qemu-system-x86_64 \
      -smp 2 -cpu max -m 1G \
      -drive file=output/disk-qemu.vmdk,if=ide,id=drv0 \
      -netdev "user,id=net0,${fwd}" -device virtio-net-pci,netdev=net0 \
      -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
      -kernel output/ifs.bin \
      -display none -serial "file:$LOG" -monitor none \
      -pidfile "$PIDFILE" -daemonize )
  echo "booting (pid $(cat "$PIDFILE")); console: $LOG"
}

cmd_wait() {
  local t0=$SECONDS limit="${1:-180}"
  until ssh "${SSH_OPTS[@]}" root@127.0.0.1 true 2>/dev/null; do
    running || die "QEMU exited; see $LOG"
    (( SECONDS - t0 < limit )) || die "ssh not up after ${limit}s; see $LOG"
    sleep 2
  done
  echo "ssh up after $((SECONDS - t0))s"
}

cmd_ssh()  { ssh "${SSH_OPTS[@]}" root@127.0.0.1 "$@"; }
cmd_scp()  {
  [ $# -ge 2 ] || die "usage: scp <src...> <target-dst>"
  local dst="${!#}"; set -- "${@:1:$#-1}"
  scp -q -O -i "$KEY" -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR "$@" "root@127.0.0.1:$dst"
}
cmd_stop() {
  running || { echo "not running"; rm -f "$PIDFILE"; return 0; }
  # qnx6 commits lazily: flush the guest first or recent writes are lost
  ssh "${SSH_OPTS[@]}" root@127.0.0.1 sync 2>/dev/null || true
  kill "$(cat "$PIDFILE")" && rm -f "$PIDFILE" && echo "stopped"
}
cmd_status()  { running && echo "running (pid $(cat "$PIDFILE"))" || echo "stopped"; }
cmd_console() { tail -n 200 -f "$LOG"; }

sub="${1:-}"; shift || true
case "$sub" in
  image|start|wait|ssh|scp|stop|status|console) "cmd_$sub" "$@" ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
