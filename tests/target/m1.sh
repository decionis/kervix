#!/usr/bin/env bash
# M1 acceptance on QNX 8.0 (QEMU): vsimd + kervixd + sdv_actuatord + kxctl.
# The six plan checks (docs/04-implementation-plan.md §4) plus attacks and
# fail-closed behaviour. Usage: tests/target/m1.sh  (make target-m1)
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
start_all() { T '(./vsimd > /tmp/vsimd.log 2>&1 &); (./kervixd -v > /tmp/kervixd.log 2>&1 &); (./sdv_actuatord -v > /tmp/act.log 2>&1 &); sleep 1.5'; }
start_all
K='./kxctl'
# run on target, capture output + exit code: "OUT|||<code>"
R() { T "$* ; echo \"|||\$?\"" 2>&1 || true; }
code() { echo "$1" | sed -n 's/.*|||\([0-9]*\)$/\1/p' | tail -1; }
has()  { echo "$1" | grep -q "$2"; }
door_mask() { T "$K telemetry" | awk '/doors_locked_mask/{print $2}'; }
park() { T "$K sim scenario park >/dev/null"; for _ in $(seq 1 30); do T "$K sim status" | grep -q 'speed_dkph=0 gear=P' && return 0; sleep 1; done; return 1; }

echo "== plan checks"
# 1. parked: ALLOW -> executed -> telemetry changes
o=$(R "$K propose --exec body.door.unlock door=rear_right")
has "$o" "^ALLOW .*door-unlock-parked" && has "$o" "EXECUTED" && [ "$(door_mask)" = 7 ] \
  && pass "1 parked door unlock: ALLOW -> grant -> actuated (lock mask 15 -> 7)" || bad "1 $o"

# 2. moving: BLOCK
T "$K sim scenario highway >/dev/null"; sleep 4
o=$(R "$K propose --exec body.door.unlock door=front_left")
has "$o" "^BLOCK .*VEHICLE_MOVING" && [ "$(code "$o")" = 4 ] && pass "2 door unlock at speed: BLOCK VEHICLE_MOVING (exit 4)" || bad "2 $o"
park || bad "could not park"

# 3. replay
o=$(R "$K propose --replay light.hazard.set on=1")
has "$o" "execute  EXECUTED" && has "$o" "replay   REFUSED   GRANT_SPENT" && pass "3 replay of a spent grant: GRANT_SPENT" || bad "3 $o"

# 4. expiry (TTL 250 ms)
o=$(R "$K propose --delay-ms 400 light.hazard.set on=0")
has "$o" "REFUSED   GRANT_EXPIRED" && pass "4 grant presented after 400 ms (TTL 250): GRANT_EXPIRED" || bad "4 $o"

# 5. TOCTOU: vehicle starts moving between grant and actuation
#    (a scenario change takes effect on the simulator's next 10 ms tick: wait
#    120 ms so the car is actually rolling, still inside the 250 ms grant TTL)
o=$(R "$K propose --sim 'scenario highway' --delay-ms 120 body.door.unlock door=front_right")
has "$o" "REFUSED   GRANT_INTERLOCK" && pass "5 car pulls away after approval: GRANT_INTERLOCK (no actuation)" || bad "5 $o"
park || bad "could not park"

# 6. stale telemetry: safety actions blocked, two-way comfort still allowed
T "$K sim stall 1 >/dev/null"; sleep 0.3
o=$(R "$K propose body.door.unlock door=front_left"); o2=$(R "$K propose cabin.climate.set temp_dc=200")
has "$o" "^BLOCK .*TELEMETRY_STALE" && has "$o2" "^ALLOW" && pass "6 telemetry stalled: door BLOCK TELEMETRY_STALE, climate still ALLOW (K1)" || bad "6 $o $o2"
T "$K sim stall 0 >/dev/null"; sleep 0.3

echo "== attacks"
o=$(R "$K propose --forge cabin.climate.set temp_dc=190")
has "$o" "REFUSED   GRANT_MAC" && pass "forged grant (1 MAC bit): GRANT_MAC" || bad "forge $o"
o=$(R "$K propose --mutate door=front_right body.door.unlock door=front_left")
has "$o" "REFUSED   GRANT_PARAMS" && pass "approved door A, tried door B: GRANT_PARAMS" || bad "mutate $o"
o=$(R "$K propose --save-grant /tmp/g.bin cabin.climate.set temp_dc=215; $K execute --grant /tmp/g.bin")
has "$o" "REFUSED   GRANT_BINDING" && pass "grant stolen and presented by another process: GRANT_BINDING" || bad "binding $o"
T "$K sim spoof speed_dkph 600 >/dev/null"   # parked in P, but published "60 km/h"
o=$(R "$K propose cabin.climate.set temp_dc=220")
has "$o" "^BLOCK .*TELEMETRY_IMPLAUSIBLE" && pass "spoofed telemetry (gear P at 60 km/h): BLOCK TELEMETRY_IMPLAUSIBLE (K2)" || bad "spoof $o"
T "$K sim spoof off >/dev/null"
o=$(R "$K propose cabin.climate.set temp_dc=999")
has "$o" "^BLOCK .*PARAM_INVALID" && pass "out-of-range parameter: BLOCK PARAM_INVALID (K4)" || bad "range $o"

echo "== R156 OTA journey"
T "$K sim scenario highway >/dev/null"; sleep 3
D=sha256:0101010101010101010101010101010101010101010101010101010101010101
o=$(R "$K propose ota.ecu.flash ecu=brake image_digest=$D")
has "$o" "^BLOCK .*R156_NOT_SAFE_STATE" && pass "OTA at speed: BLOCK R156_NOT_SAFE_STATE" || bad "ota moving $o"
park || bad "could not park"
o=$(R "$K propose ota.ecu.flash ecu=brake image_digest=$D")
has "$o" "^ESCALATE .*DRIVER_CONSENT" && [ "$(code "$o")" = 3 ] && pass "OTA parked: ESCALATE to the driver (exit 3)" || bad "ota parked $o"

echo "== stats"
T "$K stats" | sed 's/^/INFO  /'

echo "== fail closed"
o=$(R "$K propose --save-grant /tmp/g2.bin --delay-ms 0 cabin.climate.set temp_dc=205")  # executes once, fine
T 'slay -f kervixd; sleep 0.3'
o=$(R "$K propose --exec cabin.climate.set temp_dc=210")
has "$o" "is kervixd running" && pass "authority down: proposals impossible" || bad "down propose $o"
o=$(R "$K propose --save-grant /tmp/g3.bin cabin.climate.set temp_dc=211" ; true)
T '(./kervixd -v > /tmp/kervixd2.log 2>&1 &); sleep 1'
o=$(R "$K propose --save-grant /tmp/g4.bin cabin.climate.set temp_dc=212")
T 'slay -f kervixd; sleep 0.3'
o=$(R "$K execute --grant /tmp/g4.bin")
has "$o" "REFUSED   AUTHORITY_UNAVAILABLE" && pass "authority down: actuator refuses everything (AUTHORITY_UNAVAILABLE)" || bad "down exec $o"
T '(./kervixd -v > /tmp/kervixd3.log 2>&1 &); sleep 1'
o=$(R "$K execute --grant /tmp/g4.bin")
has "$o" "REFUSED   GRANT_MAC" && pass "after restart: pre-restart grant rejected (new per-boot key)" || bad "restart $o"

T 'slay -f vsimd kervixd sdv_actuatord >/dev/null 2>&1; true'
[ $fail -eq 0 ] && echo "M1 RESULT: PASS" || { echo "M1 RESULT: FAIL"; exit 1; }
