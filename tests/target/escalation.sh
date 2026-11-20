#!/usr/bin/env bash
# Escalation (human oversight) acceptance on QNX 8.0 (QEMU).
# Usage: tests/target/escalation.sh   (make target-escalation)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
B=build/qnx-x86_64/target
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }

make -s target-x86_64 >/dev/null
$Q status | grep -q running || { $Q start >/dev/null; $Q wait 180 >/dev/null; }
$Q ssh 'slay -f vsimd kervixd sdv_actuatord >/dev/null 2>&1; mkdir -p /data/kervix/bin; cd /data/kervix/bin && rm -f vsimd kervixd sdv_actuatord kxctl'
$Q scp $B/vsimd/vsimd $B/kervixd/kervixd $B/sdv_actuatord/sdv_actuatord $B/kxctl/kxctl /data/kervix/bin/
T() { $Q ssh "cd /data/kervix/bin && $*"; }
T '(./vsimd > /tmp/vsimd.log 2>&1 &); (./kervixd -v > /tmp/kervixd.log 2>&1 &); (./sdv_actuatord -v > /tmp/act.log 2>&1 &); sleep 1.5'
K=./kxctl
D=sha256:0101010101010101010101010101010101010101010101010101010101010101
R() { T "$* ; echo \"|||\$?\"" 2>&1 || true; }
has() { echo "$1" | grep -q "$2"; }
# start an awaiting proposal in the background on the target; prints nothing
# (stdio fully detached: otherwise ssh waits for the background job to finish)
# One remote session per scenario: start an AWAITing agent, wait until its
# escalation is listed, run the resolution snippet (may use $id), then wait for
# the agent and print "LIST", "AGENT" sections. (A REPLY-blocked process keeps
# QNX sshd from closing a session, so waiter and resolver share one session.)
pending_id() { T "$K escalations" | sed -n "s/^#\\([0-9]*\\)  $1 .*/\\1/p" | head -1; }
esc() { # <action name> "<propose args>" "<resolution snippet>"
  T "rm -f /tmp/esc.out; $K propose --await $2 > /tmp/esc.out 2>&1 & p=\$!
     id=''; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
       id=\$($K escalations | sed -n 's/^#\\([0-9]*\\)  $1 .*/\\1/p' | head -1); [ -n \"\$id\" ] && break; sleep 0.2; done
     echo LIST; $K escalations; echo ID=\$id
     $3
     wait \$p; echo \"|||\$?\" >> /tmp/esc.out; echo AGENT; cat /tmp/esc.out"
}
park() { T "$K sim scenario park >/dev/null"; for _ in $(seq 1 30); do T "$K sim status" | grep -q 'speed_dkph=0 gear=P' && return 0; sleep 1; done; return 1; }

echo "== approve"
o=$(esc ota.ecu.flash "--exec ota.ecu.flash ecu=brake image_digest=$D" "$K approve \$id --as hmi:driver-seat >/dev/null")
id=$(echo "$o" | sed -n 's/^ID=//p')
has "$o" "^#$id  ota.ecu.flash .*DRIVER_CONSENT .*rule=ota-escalate" && pass "HMI sees pending #$id: ota.ecu.flash, DRIVER_CONSENT, countdown" || bad "list: $o"
has "$o" "^ALLOW    escalation #$id resolved" && has "$o" "HUMAN_APPROVED" && has "$o" "execute  EXECUTED" \
  && pass "driver approves -> agent unblocked with a fresh grant -> OTA executed" || bad "approve: $o"
[ "$(T "$K telemetry" | awk '/ota_state/{print $2}')" = 1 ] && pass "vehicle reports OTA flashing" || bad "ota_state"

echo "== deny"
o=$(esc telematics.location.share "telematics.location.share recipient=fleet_operator duration_s=3600" "$K deny \$id --as hmi:driver-seat >/dev/null")
has "$o" "^BLOCK    escalation #[0-9]* resolved" && has "$o" "HUMAN_DENIED" && has "$o" "|||4" && pass "driver denies location sharing -> BLOCK HUMAN_DENIED" || bad "deny: $o"

echo "== timeout (fail closed)"
o=$(esc adas.acc.set_speed "adas.acc.set_speed target_kph=125" ':')
has "$o" "ESCALATE adas.acc.set_speed .*SPEED_DELTA_LARGE" && has "$o" "ESCALATION_TIMEOUT" && pass "nobody answers within the rule's 10 s -> BLOCK ESCALATION_TIMEOUT" || bad "timeout: $o"

echo "== situation changes while the driver decides"
sleep 9   # let the earlier OTA flash (8 s, vehicle immobilized) finish
o=$(esc ota.ecu.flash "--exec ota.ecu.flash ecu=brake image_digest=$D" "$K sim scenario highway >/dev/null; sleep 1.5; $K approve \$id >/dev/null")
has "$o" "^BLOCK    escalation #[0-9]* resolved" && has "$o" "R156_NOT_SAFE_STATE" && ! has "$o" "EXECUTED" \
  && pass "car drove off before approval: approval re-evaluated -> BLOCK R156_NOT_SAFE_STATE, nothing executed" || bad "re-eval: $o"
park || bad "could not park"

echo "== an interrupted agent is released immediately (unblock handling)"
o=$(T ":; $K propose --await ota.ecu.flash ecu=brake image_digest=$D > /tmp/y.out 2>&1 & p=\$!; sleep 1; t0=\$(date +%s); kill -TERM \$p; wait \$p; echo \"released=\$(( \$(date +%s) - t0 ))s\"")
l=$(T "$K escalations")
has "$o" "released=0s" && has "$l" "ota.ecu.flash" \
  && pass "SIGTERM to an agent blocked in AWAIT: released at once; escalation stays pending for the driver" || bad "unblock: $o / $l"
id=$(pending_id ota.ecu.flash); T "$K deny $id >/dev/null"

echo "== binding, bookkeeping, preconditions"
o=$(R "$K propose ota.ecu.flash ecu=brake image_digest=$D"); id=$(echo "$o" | sed -n 's/.*escalation #\([0-9]*\).*/\1/p')
o=$(R "$K await $id")
has "$o" "only the proposing process" && pass "another process cannot hijack the escalation (AWAIT: EPERM)" || bad "await binding: $o"
T "$K approve $id >/dev/null"
o=$(R "$K approve $id"); has "$o" "already resolved" && has "$o" "|||1" && pass "double approval rejected (already resolved)" || bad "double: $o"
o=$(R "$K approve 9999"); has "$o" "no such escalation" && pass "unknown escalation id rejected" || bad "unknown: $o"
T "$K sim driver 0 >/dev/null"
o=$(R "$K propose ota.ecu.flash ecu=brake image_digest=$D")
has "$o" "^BLOCK .*DRIVER_ABSENT" && pass "no driver in the seat: nobody to ask -> BLOCK DRIVER_ABSENT (no escalation)" || bad "absent: $o"
T "$K sim driver 1 >/dev/null"
has "$(T "$K escalations")" "no pending escalations" && pass "queue empty after resolution" || bad "queue not empty"
T "$K stats" | grep -E "^escalations" | sed 's/^/INFO  /'

T 'slay -f vsimd kervixd sdv_actuatord >/dev/null 2>&1; true'
[ $fail -eq 0 ] && echo "ESCALATION RESULT: PASS" || { echo "ESCALATION RESULT: FAIL"; exit 1; }
