#!/usr/bin/env bash
# kx-selftest on QNX 8.0 (QEMU): boot a fresh image, run the on-target selftest
# (every safety and security scenario, one PASS/FAIL table), then verify the
# run's signed dossier offline on this host (J6).
#   tests/target/selftest.sh [open|secure] [-q]   (make target-selftest / target-selftest-secure)
#   open   = dev image: --secpol=open, every Kervix type restricted
#   secure = release image: --secpol=secure (kervix + harvested system + monitor policy)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
MODE=${1:-open}; QUICK=${2:-}
. tests/target/secpol-lib.sh
make -s target-x86_64 >/dev/null
$Q stop >/dev/null || true
if [ "$MODE" = secure ]; then
  POLICY=build/kervix-secure.secpol
  cat target/secpol/kervix.secpol target/secpol/system.secpol target/secpol/monitor.secpol > $POLICY
else
  POLICY=target/secpol/kervix.secpol
fi
KX_SNIPPETS=target/image/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=$MODE --policy=/work/$POLICY --secure-procfs=yes" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null
if [ "$MODE" = open ]; then
  $Q ssh "for t in $KX_TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; rm -rf /data/kervix/ledger /data/kervix/keys; sync"
  $Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
fi
for _ in $(seq 1 40); do $Q ssh 'grep -q "kervixd: ready" /tmp/kervixd.log' 2>/dev/null && break; sleep 0.5; done

$Q ssh "/system/bin/kervix/kx-selftest $QUICK" | tee build/selftest-$MODE.txt || true
rm -rf build/selftest-dossier
scp -q -O -r -i vm/ssh/kervix_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  root@127.0.0.1:/tmp/kx-selftest-dossier build/selftest-dossier
echo "== J6 on this host: offline verification of the run's dossier"
v=$(node host/verify/kervix-verify.mjs build/selftest-dossier || true)
echo "$v" | tail -12
grep -q "^SELFTEST RESULT: PASS" build/selftest-$MODE.txt && echo "$v" | grep -q "^VERIFIED" \
  && echo "TARGET SELFTEST ($MODE): PASS" || { echo "TARGET SELFTEST ($MODE): FAIL"; exit 1; }
