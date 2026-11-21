#!/usr/bin/env bash
# The codelab, end to end, as a test: every step of codelab/README.md in order.
# Needs the QNX SDP 8.0 build container and QEMU (docs/setup-macos.md, or a Linux host).
#   codelab/run.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
Q=scripts/qemu.sh
BIN=build/qnx-x86_64/codelab/carlock
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
has()  { echo "$1" | grep -q -- "$2"; }
TYPES="carlockd_t carlockd_run_t app_t keyfob_t"
CL=/data/codelab

echo "== step 2: build the daemon, the client and the policy"
make -s target-x86_64 >/dev/null
docker/qnx-build.sh secpolcompile -o build/carlock.secpol.bin /work/codelab/carlock/carlock.secpol && pass "secpolcompile accepts carlock.secpol"

echo "== step 3: an image with the policy (open mode: secpolgenerate learns, our types will be held to it)"
$Q stop >/dev/null || true
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/codelab/carlock/carlock.secpol" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null
$Q ssh "mkdir -p $CL; rm -f $CL/*" && $Q scp $BIN/carlockd $BIN/carlock $CL/ >/dev/null
run() { $Q ssh "cd $CL && (on -T carlockd_t ./carlockd > carlockd.log 2>&1 &); sleep 1
  echo '-- app_t status';   on -T app_t ./carlock status
  echo '-- app_t unlock';   on -T app_t ./carlock unlock
  echo '-- keyfob_t unlock'; on -T keyfob_t ./carlock unlock
  echo '-- keyfob_t lock';  on -T keyfob_t ./carlock lock
  echo '-- app_t squat';    on -T app_t ./carlock squat
  echo '-- carlockd';       cat carlockd.log; slay -f carlockd >/dev/null 2>&1; true" 2>&1; }
section() { echo "$1" | awk -v s="-- $2" '$0 == s {f=1; next} /^-- / {f=0} f'; }

echo "== step 4: before enforcement (types exist but are not restricted)"
o=$(run)
has "$(section "$o" "app_t unlock")" "unlock: OK" && pass "without enforcement, the infotainment app CAN unlock the car" || bad "baseline: $o"

echo "== step 5: restrict our types, reboot"
$Q ssh "for t in $TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; sync"
$Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
o=$(run)
echo "$o" | sed 's/^/      /'
has "$(section "$o" "app_t status")" "status: OK, the car is LOCKED (carlockd saw caller type app_t)" && pass "app_t reads the lock state; carlockd sees its type from the message" || bad "status"
has "$(section "$o" "app_t unlock")" "REFUSED: open /dev/carlock/command: Operation not permitted" && pass "app_t (as root!) cannot even open the command path: EPERM from the kernel" || bad "app unlock"
has "$(section "$o" "keyfob_t unlock")" "unlock: OK, the car is UNLOCKED" && has "$(section "$o" "keyfob_t lock")" "lock: OK, the car is LOCKED" && pass "keyfob_t unlocks and locks" || bad "keyfob"
has "$(section "$o" "app_t squat")" "squat: REFUSED: Operation not permitted" && pass "app_t cannot impersonate carlockd (no pathspace ability: EPERM)" || bad "squat"
has "$(section "$o" "carlockd")" "running as type carlockd_run_t" && pass "carlockd dropped its privileges after attaching (carlockd_run_t)" || bad "drop"

echo "== step 6: the kernel says why"
d=$($Q ssh "slog2info | grep secpolgenerate | grep -E 'app_t' | tail -3")
echo "$d" | sed 's/^/      /'
has "$d" "channel_connect:carlock_command_ch_t" && has "$d" "failed to use ability pathspace" && pass "the refusal log names what app_t was denied: the command channel, and pathspace" || bad "log: $d"

$Q stop >/dev/null
[ $fail -eq 0 ] && echo "CODELAB RESULT: PASS" || { echo "CODELAB RESULT: FAIL"; exit 1; }
