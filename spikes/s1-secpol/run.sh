#!/usr/bin/env bash
# Spike S1/S2: reproducible end-to-end check of kernel-enforced channel typing.
#   1. build the QEMU image with --secpol=open and spikes/s1-secpol/s1.secpol
#      as secpolgenerate's base policy
#   2. mark the spike types `restricted` (held to the policy; rest of the
#      system stays permissive) and reboot so secpolgenerate reloads config
#   3. run server + clients under their types and assert the access matrix
# Usage: spikes/s1-secpol/run.sh            (from the repo root)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

Q=scripts/qemu.sh
BIN=build/qnx-x86_64/spikes/s1-secpol
fail=0

echo "== build"
make -s target-x86_64 >/dev/null
docker/qnx-build.sh secpolcompile -o build/s1.secpol.bin spikes/s1-secpol/s1.secpol
$Q stop >/dev/null || true
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/spikes/s1-secpol/s1.secpol" $Q image >/dev/null

echo "== boot + restrict spike types"
$Q start >/dev/null && $Q wait 180
$Q ssh 'for t in s1_server_t s1_server_run_t s1_agent_t s1_actuator_t; do
          grep -qx "type $t restricted" /data/var/secpol/config || echo "type $t restricted" >> /data/var/secpol/config
        done; mkdir -p /data/kervix/s1; sync'
$Q scp build/s1.secpol.bin /data/var/secpol/secpol.bin
$Q scp "$BIN/s1_server" "$BIN/s1_client" /data/kervix/s1/
$Q ssh sync
$Q stop >/dev/null && $Q start >/dev/null && $Q wait 180

echo "== run"
OUT=$($Q ssh 'cd /data/kervix/s1 && (on -T s1_server_t ./s1_server > server.log 2>&1 &); sleep 1.5
  echo "AS s1_agent_t";    on -T s1_agent_t ./s1_client all
  echo "AS s1_actuator_t"; on -T s1_actuator_t ./s1_client all
  echo "SERVER"; cat server.log
  echo "DENIALS"; slog2info | grep secpolgenerate | grep -E "s1_" | tail -n 8
  slay -f s1_server >/dev/null 2>&1; true')
echo "$OUT"

expect() { # <section> <regex> <label>
  local section; section=$(echo "$OUT" | awk -v s="$1" '$0 ~ "^AS "s {f=1; next} /^AS |^SERVER/ {f=0} f')
  if echo "$section" | grep -Eq "$2"; then echo "PASS  $3"; else echo "FAIL  $3"; fail=1; fi
}
expect s1_agent_t    'RESULT OPEN ok .*type=s1_agent_t'   "agent reaches open channel; server sees its type (S2)"
expect s1_agent_t    'RESULT PRIV denied'                 "agent DENIED actuator-only channel by the kernel"
expect s1_agent_t    'RESULT SQUAT denied'                "agent cannot squat a Kervix path"
expect s1_agent_t    'RESULT PULSE ok'                    "registered pulse delivered (MsgRegisterEvent)"
expect s1_actuator_t 'RESULT PRIV ok .*type=s1_actuator_t' "actuator reaches actuator-only channel"
expect s1_actuator_t 'RESULT SQUAT denied'                "actuator cannot squat either"
if echo "$OUT" | grep -q 'forbidden (not in policy) -> -1'; then echo "PASS  server cannot attach a path without allow_attach"; else echo "FAIL  server attach not enforced"; fail=1; fi
if echo "$OUT" | grep -q 'now type=.*(s1_server_run_t)'; then echo "PASS  server dropped privileges (secpol_transition_type)"; else echo "FAIL  privilege drop"; fail=1; fi

$Q stop >/dev/null
[ $fail -eq 0 ] && echo "S1 RESULT: PASS" || { echo "S1 RESULT: FAIL"; exit 1; }
