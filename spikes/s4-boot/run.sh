#!/usr/bin/env bash
# Spike S4: services baked into the QNX image and started at boot, reachable
# from the host through QEMU user-mode port forwards (7301-7303).
#   1. build s4_gw, install it via mkqnximage snippets (system_files/post_start)
#   2. boot; each role starts with its own secpol type + priority
#   3. from the HOST: connect to each port, assert role/prio/type/echo
# Usage: spikes/s4-boot/run.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
fail=0

make -s target-x86_64 >/dev/null
$Q stop >/dev/null || true
KX_SNIPPETS=spikes/s4-boot/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/spikes/s4-boot/s4.secpol" $Q image >/dev/null

t0=$(date +%s)
$Q start >/dev/null
expect() { # <port> <role> <prio> <type>
  local r="" deadline=$((t0 + 180))
  until r=$(printf 'hello-%s\n' "$1" | nc -w 2 127.0.0.1 "$1" 2>/dev/null) && [ -n "$r" ]; do
    [ "$(date +%s)" -lt $deadline ] || break
    sleep 1
  done
  echo "  :$1 -> ${r:-<no answer>}"
  if echo "$r" | grep -q "\"role\":\"$2\",.*\"prio\":$3,\"type\":\"$4\".*\"echo\":\"hello-$1\""; then
    echo "PASS  $2 gateway on :$1 (prio $3, type $4) reachable from host"
  else
    echo "FAIL  $2 gateway on :$1"; fail=1
  fi
}
expect 7301 agent 10 kxgw_agent_t
expect 7302 hmi 30 kxgw_hmi_t
expect 7303 observer 5 kxgw_obs_t
echo "INFO  all gateways answered $(( $(date +%s) - t0 ))s after QEMU start (TCG emulation)"
grep "kxgw\[" vm/qemu-x86_64/console.log | sed 's/^/INFO  console: /'
if [ "$(grep -c 'kxgw\[.*listening' vm/qemu-x86_64/console.log)" -eq 3 ]; then
  echo "PASS  all three roles started from the boot script (post_start.custom)"
else
  echo "FAIL  boot-time start"; fail=1
fi
$Q stop >/dev/null
[ $fail -eq 0 ] && echo "S4 RESULT: PASS" || { echo "S4 RESULT: FAIL"; exit 1; }
