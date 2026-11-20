#!/usr/bin/env bash
# host/bridge end to end against QNX 8.0 (QEMU): REST + WebSocket -> kxgw -> kervixd.
# Boots the gateway image (as tests/target/kxgw.sh) unless its gateways already answer.
# Usage: tests/target/bridge.sh   (make target-bridge)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
if ! node tests/target/kxgw-client.mjs --timeout 3000 7304 '{"op":"hello","id":"h"}' 2>/dev/null | grep -q '"type":"worldgw_t"'; then
  . tests/target/secpol-lib.sh
  make -s target-x86_64 >/dev/null
  $Q stop >/dev/null || true
  KX_SNIPPETS=target/image/snippets \
  KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/target/secpol/kervix.secpol --secure-procfs=yes" $Q image >/dev/null
  $Q start >/dev/null && $Q wait 180 >/dev/null
  $Q ssh "for t in $KX_TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; sync"
  $Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
  sleep 3
fi
node tests/target/bridge-e2e.ts
