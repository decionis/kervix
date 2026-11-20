#!/usr/bin/env bash
# Kernel-enforced least privilege for every Kervix component (QNX 8.0 secpol).
#   1. image: Kervix daemons baked in and started at boot under their secpol
#      types (target/image/snippets), policy target/secpol/kervix.secpol,
#      --secure-procfs; secpolgenerate holds every Kervix type `restricted`
#   2. every legitimate role works with ZERO denials
#   3. kx-rogue, run as the agent's type, is refused by the kernel
#   open   (default) --secpol=open dev image: secpolgenerate learns for the
#          system, every Kervix type held `restricted`; shows the baseline too
#   secure --secpol=secure release image: ONE complete policy, no learning,
#          nothing unrestricted (kervix.secpol + the harvested system.secpol
#          + monitor.secpol from scripts/secpol-harvest.sh); even root's shell is confined
# Usage: tests/target/secpol.sh [open|secure]   (make target-secpol / target-secpol-secure)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
has()  { echo "$1" | grep -q -- "$2"; }
. tests/target/secpol-lib.sh

MODE=${1:-open}
case $MODE in open|secure) ;; *) echo "usage: $0 [open|secure]"; exit 2;; esac
if [ "$MODE" = secure ]; then
  POLICY=build/kervix-secure.secpol
  cat target/secpol/kervix.secpol target/secpol/system.secpol target/secpol/monitor.secpol > $POLICY
  denials() { echo "{ on -T operator_t cat /dev/secpolgenerate/errors || echo MONITOR-MISSING; } | grep -v '^#' | grep -v '^\$'"; }
else
  POLICY=target/secpol/kervix.secpol
  denials() { echo "slog2info | grep secpolgenerate | grep -E 'type:(vsim|kervix|actuator|agentgw|hmigw|operator)'"; }
fi

echo "== build $MODE image (daemons at boot, typed)"
make -s target-x86_64 >/dev/null
docker/qnx-build.sh secpolcompile -o build/kervix.secpol.bin /work/$POLICY
$Q stop >/dev/null || true
KX_SNIPPETS=target/image/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=$MODE --policy=/work/$POLICY --secure-procfs=yes" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null || { bad "secure image did not come up (ssh)"; echo "SECPOL RESULT ($MODE): FAIL"; exit 1; }

if [ "$MODE" = open ]; then
echo "== baseline: every Kervix type UNRESTRICTED (what an agent could do without the policy)"
o=$($Q ssh "on -T agentgw_t /system/bin/kervix/kx-rogue --kervixd-pid $(kx_kervixd_pid); true")
nb=$(echo "$o" | sed -n 's/^kx-rogue: \([0-9]*\) attack(s) OPEN/\1/p')
echo "$o" | grep -E "^(OPEN|BLOCKED)" | sed 's/^/INFO  /'
[ "${nb:-0}" -ge 9 ] && pass "baseline without enforcement: $nb/10 attacks OPEN" || bad "baseline: expected most attacks open, got $nb"

echo "== enforce: restrict every Kervix type, reboot"
$Q ssh "for t in $KX_TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; rm -rf /data/kervix/ledger /data/kervix/keys; sync"
$Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
else
echo "== secure: one complete policy, nothing learns, nothing runs untyped"
o=$($Q ssh 'pidin -f an_ | awk "NR>1 && \$NF==\"-\" {print \$2}"')
untyped=$(echo "$o" | grep -v procnto || true)
[ -z "$untyped" ] && pass "every process runs under a secpol type (procnto aside)" || bad "untyped processes: $untyped"
o=$($Q ssh 'pidin -f an_ | grep secpolgen_t; on -T operator_t ls /dev/secpolgenerate/errors 2>&1; ls /proc/boot/secpol.bin /data/var/secpol/secpol.bin 2>&1; true')
has "$o" "secpolgen_t" && has "$o" "^/dev/secpolgenerate/errors" && has "$o" "^/proc/boot/secpol.bin" && has "$o" "/data/var/secpol/secpol.bin: No such file" \
  && pass "no learning: policy fixed in the boot image, secpolgenerate only monitors (secpolgen_t)" || bad "monitor: $o"
fi
o=$($Q ssh 'pidin -F "%a %N" | grep -E "vsimd|kervixd|sdv_actuatord"; cat /tmp/vsimd.log /tmp/kervixd.log /tmp/sdv_actuatord.log')
has "$o" "vsimd: ready" && has "$o" "kervixd: ready" && has "$o" "sdv_actuatord: ready" \
  && pass "vsimd, kervixd, sdv_actuatord start at boot under restricted types" || bad "daemons: $o"

echo "== legitimate roles: zero denials"
o=$($Q ssh "$KX_ROLES
  echo DENIALS; $(denials) || true")
has "$o" "execute  EXECUTED" && pass "agent (agentgw_t, uid 400): propose -> grant -> actuate" || bad "agent exec"
has "$o" "replay   REFUSED   GRANT_SPENT" && pass "agent replay still refused (crypto layer)" || bad "replay"
has "$o" "HUMAN_APPROVED" && pass "agent escalates, driver HMI (hmigw_t) approves" || bad "hmi"
echo "$o" | grep -Eq "rate=(9[0-9]|1[0-9][0-9])\.[0-9]Hz.* seq_regressions=0" && has "$o" "^ledger OK" && has "$o" "exported" \
  && pass "operator (operator_t): telemetry, stats, ledger export" || bad "operator: $(echo "$o" | grep -E 'rate=|^ledger|exported|rror')"
[ -z "$(echo "$o" | sed -n '/^DENIALS/,$p' | tail -n +2)" ] && pass "no secpol denials for any legitimate role" || bad "denials: $(echo "$o" | sed -n '/^DENIALS/,$p')"

echo "== red team under enforcement"
o=$($Q ssh "on -T agentgw_t /system/bin/kervix/kx-rogue --kervixd-pid $(kx_kervixd_pid); true")
echo "$o" | grep -E "^(OPEN|BLOCKED)" | sed 's/^/INFO  [root] /'
for a in "actuate the bus directly" "raw maintenance path" "redeem a forged grant" "approve its own escalation" "rewrite vehicle state" "impersonate the authority" "impersonate the actuator bus"; do
  echo "$o" | grep -q "^BLOCKED  kernel   .*$a" && pass "secpol alone (agent as root) blocks: $a" || bad "not blocked by secpol: $a"
done
o=$($Q ssh "on -T agentgw_t -u 400:400 /system/bin/kervix/kx-rogue --kervixd-pid $(kx_kervixd_pid); echo EXIT=\$?")
echo "$o" | grep -E "^(OPEN|BLOCKED)" | sed 's/^/INFO  [uid 400] /'
has "$o" "EXIT=0" && pass "deployed agent (agentgw_t, uid 400): 0/10 attacks open" || bad "attacks open as uid 400: $o"
$Q ssh "$(denials | sed 's/grep -E .*//; s/| *$//') | grep kx-rogue | sed 's/.*secpolgenerate.[0-9]* *info *0 *//; s/^[0-9-]* [0-9:]* //; s/(pid:[0-9]* /(/' | sort -u" | sed 's/^/INFO  kernel log: /'
if [ "$MODE" = secure ]; then
  o=$($Q ssh 'ln -sPf /proc/boot/echo /data/kx-escape 2>&1; echo RC=$?')
  has "$o" "RC=0" && bad "root shell could create a process-manager symlink: $o" || pass "even root's shell is confined: new pathspace link refused (not in the harvested policy)"
  o=$($Q ssh 'for t in kervix_t actuator_t vsim_t; do on -T $t /proc/boot/echo started 2>&1; done; true')
  [ "$(echo "$o" | grep -c "on: Operation not permitted")" = 3 ] && ! has "$o" started \
    && pass "root cannot start anything as kervix_t / actuator_t / vsim_t (kernel refuses settypeid: no fake authority or actuator)" \
    || bad "root could start a process as a trusted type: $o"
  # J5 on the release image: only supervisor_t may start the authority, and it does
  $Q ssh 'slay -9 -f kervixd; true' >/dev/null
  for _ in $(seq 1 40); do $Q ssh 'grep -q "restart #1" /tmp/kervixd.log' && break; sleep 0.5; done
  o=$($Q ssh "grep 'restart #1' /tmp/kervixd.log; $(denials) | grep -E 'type:(kervix|supervisor)' || true")
  has "$o" "authority back in .* after SIGKILL (restart #1" && ! has "$o" "type:" \
    && pass "kill -9 kervixd: kx-supervisor (supervisor_t) restarts it under the secure policy: $(echo "$o" | sed -n 's/.*\(back in [0-9.]* ms\).*/\1/p')" \
    || bad "supervised restart on the secure image: $o"
fi

[ $fail -eq 0 ] && echo "SECPOL RESULT ($MODE): PASS" || { echo "SECPOL RESULT ($MODE): FAIL"; exit 1; }
