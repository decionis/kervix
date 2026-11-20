#!/usr/bin/env bash
# On-target acceptance test for vsimd + kxctl (QNX 8.0 in QEMU).
# Usage: tests/target/vsim.sh        (boots the VM if needed; leaves it running)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
num()  { echo "$1" | sed -n "s/.*$2=\([-0-9.]*\).*/\1/p"; }

make -s target-x86_64 >/dev/null
$Q status | grep -q running || { $Q start >/dev/null; $Q wait 180 >/dev/null; }
$Q ssh 'slay -f vsimd >/dev/null 2>&1; mkdir -p /data/kervix/bin; rm -f /data/kervix/bin/vsimd /data/kervix/bin/kxctl'
$Q scp build/qnx-x86_64/target/vsimd/vsimd build/qnx-x86_64/target/kxctl/kxctl /data/kervix/bin/
T() { $Q ssh "cd /data/kervix/bin && $*"; }
T '(./vsimd > /tmp/vsimd.log 2>&1 &); sleep 1; cat /tmp/vsimd.log' | sed 's/^/INFO  /'

# 1. publication quality while parked
w=$(T './kxctl telemetry --watch 3'); echo "INFO  $w"
rate=$(num "$w" rate); age=$(num "$w" max_age_ms)
awk -v r="$rate" 'BEGIN{exit !(r>=90)}' && pass "rate ${rate} Hz (>= 90)" || bad "rate ${rate} Hz"
[ "$(num "$w" seq_regressions)" = 0 ] && [ "$(num "$w" seq_gaps)" = 0 ] && pass "no sequence regressions or gaps" || bad "sequence"
[ "$(num "$w" implausible)" = 0 ] && pass "all samples plausible (K2)" || bad "implausible samples while parked"
awk -v a="$age" 'BEGIN{exit !(a<50)}' && pass "max sample age ${age} ms (< 50, K1 threshold)" || bad "age ${age} ms"

# 2. driving physics + actuation through the actuate node
T './kxctl sim scenario highway >/dev/null'; sleep 6
s=$(T './kxctl telemetry'); sp=$(echo "$s" | awk '/speed_dkph/{print $2}'); gr=$(echo "$s" | awk '/ gear /{print $3}')
[ "$sp" -gt 300 ] && [ "$gr" = "(D)" ] && pass "highway: accelerating in D (speed ${sp} dkph)" || bad "highway speed=${sp} gear=${gr}"
T './kxctl sim-apply adas.acc.set_speed target_kph=80 >/dev/null && ./kxctl sim-apply cabin.climate.set temp_dc=225 >/dev/null'
sleep 8
s=$(T './kxctl telemetry')
[ "$(echo "$s" | awk '/speed_dkph/{print $2}')" = 800 ] && pass "ACC 80 km/h actuated: speed settles at 800 dkph" || bad "ACC"
[ "$(echo "$s" | awk '/hvac_setpoint_dc/{print $2}')" = 225 ] && pass "climate 22.5 C actuated" || bad "climate"
w=$(T './kxctl telemetry --watch 2'); [ "$(num "$w" implausible)" = 0 ] && pass "plausible while driving" || bad "implausible while driving"

# 3. demo hooks for the constitution
w=$(T './kxctl sim spoof gear 0 >/dev/null; ./kxctl telemetry --watch 1; ./kxctl sim spoof off >/dev/null')
p=$(num "$w" pulses); i=$(num "$w" implausible)
[ "$p" -gt 0 ] && [ "$p" = "$i" ] && pass "spoof gear=P at speed: every sample implausible (${i}/${p}), K2 will block" || bad "spoof ${i}/${p}"
age=$(T './kxctl sim stall 1 >/dev/null; sleep 0.5; ./kxctl telemetry | head -1' | sed -n 's/.*age \([0-9.]*\) ms.*/\1/p')
awk -v a="$age" 'BEGIN{exit !(a>200)}' && pass "stall: telemetry age ${age} ms, K1 will block" || bad "stall age ${age}"
age=$(T './kxctl sim stall 0 >/dev/null; sleep 0.3; ./kxctl telemetry | head -1' | sed -n 's/.*age \([0-9.]*\) ms.*/\1/p')
awk -v a="$age" 'BEGIN{exit !(a<50)}' && pass "resume: fresh again (${age} ms)" || bad "resume age ${age}"

# 4. input validation
set +e
T './kxctl sim warp 9 >/dev/null'; [ $? = 1 ] && pass "unknown sim command rejected (exit 1)" || bad "bad command accepted"
T './kxctl sim-apply nonsense.action 2>/dev/null'; [ $? = 2 ] && pass "unknown action rejected (exit 2)" || bad "bad action accepted"
T './kxctl sim set soc_dpct 5000 >/dev/null'; [ $? = 1 ] && pass "out-of-range set rejected" || bad "range check"
set -e

# 5. restart: readers keep their mapping and the sequence keeps increasing
s1=$(T './kxctl telemetry | head -1' | awk '{print $2}')
T 'slay -f vsimd; sleep 0.3; (./vsimd -s highway > /tmp/vsimd.log 2>&1 &); sleep 1'
s2=$(T './kxctl telemetry | head -1' | awk '{print $2}')
[ "$s2" -gt "$s1" ] && pass "vsimd restart: sequence continues (${s1} -> ${s2})" || bad "seq after restart ${s1} -> ${s2}"

# 6. park
T './kxctl sim scenario park >/dev/null'
for _ in $(seq 1 30); do st=$(T './kxctl sim status'); echo "$st" | grep -q "speed_dkph=0 gear=P" && break; sleep 1; done
echo "$st" | grep -q "speed_dkph=0 gear=P" && pass "park: braked to standstill, gear P" || bad "park: $st"

T 'slay -f vsimd >/dev/null 2>&1; true'
[ $fail -eq 0 ] && echo "VSIM RESULT: PASS" || { echo "VSIM RESULT: FAIL"; exit 1; }
