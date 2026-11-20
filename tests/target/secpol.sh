#!/usr/bin/env bash
# Kernel-enforced least privilege for every Kervix component (QNX 8.0 secpol).
#   1. image: Kervix daemons baked in and started at boot under their secpol
#      types (target/image/snippets), policy target/secpol/kervix.secpol,
#      --secure-procfs; secpolgenerate holds every Kervix type `restricted`
#   2. every legitimate role works with ZERO denials
#   3. kx-rogue, run as the agent's type, is refused by the kernel
# Usage: tests/target/secpol.sh   (make target-secpol)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
has()  { echo "$1" | grep -q -- "$2"; }
TYPES="vsim_t vsim_run_t kervix_t kervix_run_t actuator_t actuator_run_t agentgw_t hmigw_t operator_t"

echo "== build image (daemons at boot, typed)"
make -s target-x86_64 >/dev/null
docker/qnx-build.sh secpolcompile -o build/kervix.secpol.bin target/secpol/kervix.secpol
$Q stop >/dev/null || true
KX_SNIPPETS=target/image/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/target/secpol/kervix.secpol --secure-procfs=yes" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null

echo "== baseline: every Kervix type UNRESTRICTED (what an agent could do without the policy)"
kp() { $Q ssh 'pidin -p kervixd -F "%a" | tail -1 | tr -d " "'; }
o=$($Q ssh "on -T agentgw_t /system/bin/kervix/kx-rogue --kervixd-pid $(kp); true")
nb=$(echo "$o" | sed -n 's/^kx-rogue: \([0-9]*\) attack(s) OPEN/\1/p')
echo "$o" | grep -E "^(OPEN|BLOCKED)" | sed 's/^/INFO  /'
[ "${nb:-0}" -ge 9 ] && pass "baseline without enforcement: $nb/10 attacks OPEN" || bad "baseline: expected most attacks open, got $nb"

echo "== enforce: restrict every Kervix type, reboot"
$Q ssh "for t in $TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; rm -rf /data/kervix/ledger /data/kervix/keys; sync"
$Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
o=$($Q ssh 'pidin -F "%a %N" | grep -E "vsimd|kervixd|sdv_actuatord"; cat /tmp/vsimd.log /tmp/kervixd.log /tmp/sdv_actuatord.log')
has "$o" "vsimd: ready" && has "$o" "kervixd: ready" && has "$o" "sdv_actuatord: ready" \
  && pass "vsimd, kervixd, sdv_actuatord start at boot under restricted types" || bad "daemons: $o"

echo "== legitimate roles: zero denials"
D=sha256:0101010101010101010101010101010101010101010101010101010101010101
o=$($Q ssh "OP='on -T operator_t /system/bin/kervix/kxctl'; AG='on -T agentgw_t -u 400:400 /system/bin/kervix/kxctl'; HMI='on -T hmigw_t /system/bin/kervix/kxctl'
  \$AG propose --exec body.door.unlock door=front_left; \$AG propose --replay cabin.climate.set temp_dc=230
  \$AG propose --await --exec ota.ecu.flash ecu=brake image_digest=$D > /tmp/e.out 2>&1 & p=\$!; sleep 1
  id=\$(\$HMI escalations | sed -n 's/^#\([0-9]*\) .*/\1/p' | head -1); \$HMI approve \$id; wait \$p; cat /tmp/e.out
  \$OP telemetry --watch 1; \$OP sim status; \$OP stats; \$OP dossier export /tmp/dossier
  echo DENIALS; slog2info | grep secpolgenerate | grep -E 'type:(vsim|kervix|actuator|agentgw|hmigw|operator)' || true")
has "$o" "execute  EXECUTED" && pass "agent (agentgw_t, uid 400): propose -> grant -> actuate" || bad "agent exec"
has "$o" "replay   REFUSED   GRANT_SPENT" && pass "agent replay still refused (crypto layer)" || bad "replay"
has "$o" "HUMAN_APPROVED" && pass "agent escalates, driver HMI (hmigw_t) approves" || bad "hmi"
has "$o" "rate=1[0-9][0-9]" && has "$o" "^ledger OK" && has "$o" "exported" && pass "operator (operator_t): telemetry, stats, ledger export" || bad "operator"
[ -z "$(echo "$o" | sed -n '/^DENIALS/,$p' | tail -n +2)" ] && pass "no secpol denials for any legitimate role" || bad "denials: $(echo "$o" | sed -n '/^DENIALS/,$p')"

echo "== red team under enforcement"
o=$($Q ssh "on -T agentgw_t /system/bin/kervix/kx-rogue --kervixd-pid $(kp); true")
echo "$o" | grep -E "^(OPEN|BLOCKED)" | sed 's/^/INFO  [root] /'
for a in "actuate the bus directly" "raw maintenance path" "redeem a forged grant" "approve its own escalation" "rewrite vehicle state" "impersonate the authority" "impersonate the actuator bus"; do
  echo "$o" | grep -q "^BLOCKED  kernel   .*$a" && pass "secpol alone (agent as root) blocks: $a" || bad "not blocked by secpol: $a"
done
o=$($Q ssh "on -T agentgw_t -u 400:400 /system/bin/kervix/kx-rogue --kervixd-pid $(kp); echo EXIT=\$?")
echo "$o" | grep -E "^(OPEN|BLOCKED)" | sed 's/^/INFO  [uid 400] /'
has "$o" "EXIT=0" && pass "deployed agent (agentgw_t, uid 400): 0/10 attacks open" || bad "attacks open as uid 400: $o"
$Q ssh "slog2info | grep secpolgenerate | grep kx-rogue | sed 's/.*secpolgenerate.[0-9]* *info *0 *//; s/(pid:[0-9]* /(/' | sort -u" | sed 's/^/INFO  kernel log: /'

[ $fail -eq 0 ] && echo "SECPOL RESULT: PASS" || { echo "SECPOL RESULT: FAIL"; exit 1; }
