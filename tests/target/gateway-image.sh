# Sourced by tests/target/{bridge,agent}.sh: make sure the QEMU target runs the
# gateway image (open secpol, Kervix types restricted, kxgw x4 at boot).
# Reuses a running one when its world gateway answers as worldgw_t.
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
  for _ in $(seq 1 30); do node tests/target/kxgw-client.mjs --timeout 2000 7304 '{"op":"hello","id":"h"}' 2>/dev/null | grep -q worldgw_t && break; sleep 1; done
fi
