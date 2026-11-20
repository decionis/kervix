#!/usr/bin/env bash
# kx-bench on QNX 8.0: PROPOSE / EXECUTE latency, and the driver HMI under an
# agent flood. On QEMU/TCG the absolute numbers are emulated (the ratio flood/idle
# is what carries); headline numbers come from the RPi4 (decision H3).
# Usage: tests/target/bench.sh [kx-bench args]   (make target-bench) -> docs/evidence/bench-qnx-qemu.txt
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
. tests/target/secpol-lib.sh
make -s target-x86_64 >/dev/null
$Q stop >/dev/null || true
KX_SNIPPETS=target/image/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/target/secpol/kervix.secpol --secure-procfs=yes" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null
$Q ssh "for t in $KX_TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; rm -rf /data/kervix/ledger /data/kervix/keys; sync"
$Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
for _ in $(seq 1 40); do $Q ssh 'grep -q "kervixd: ready" /tmp/kervixd.log' 2>/dev/null && break; sleep 0.5; done
$Q ssh "on -T operator_t /system/bin/kervix/kx-bench ${*:---json}" | tee build/bench.txt
d=$($Q ssh "slog2info | grep secpolgenerate | grep -E 'type:(operator|kervix|actuator|vsim)' || true")
[ -z "$d" ] && echo "no secpol denials during the bench" || { echo "DENIALS: $d"; exit 1; }
