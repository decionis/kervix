#!/usr/bin/env bash
# kxgw: the host <-> safety-domain gateways, end to end over TCP (QEMU port
# forwards 7301-7304), with every Kervix type enforced (open secpol image,
# Kervix types restricted, as tests/target/secpol.sh):
#   - four gateways at boot, each with its own secpol type, uid and priority
#   - agent: propose -> grant -> execute; a replayed grant is refused BY THE
#     AUTHORITY (the gateway forwards it); BLOCK while moving
#   - human oversight over the network: the HMI is pushed the escalation,
#     approves it, the agent's awaiting request completes and executes
#   - least privilege: per-role op lists at the gateway, and the kernel refuses
#     the observer / world types any channel to propose
#   - hostile input: malformed, oversized and non-ASCII lines are refused, the
#     gateway stays up; the authority restarting is survived
#   - zero secpol denials; the resulting dossier verifies offline
# Usage: tests/target/kxgw.sh   (make target-kxgw)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
has()  { echo "$1" | grep -q -- "$2"; }
. tests/target/secpol-lib.sh
C="node tests/target/kxgw-client.mjs"
AGENT=7301 HMI=7302 OBS=7303 WORLD=7304
D=sha256:0101010101010101010101010101010101010101010101010101010101010101

echo "== build image: open secpol, Kervix types restricted, gateways at boot"
make -s target-x86_64 >/dev/null
$Q stop >/dev/null || true
KX_SNIPPETS=target/image/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/target/secpol/kervix.secpol --secure-procfs=yes" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null
$Q ssh "for t in $KX_TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; rm -rf /data/kervix/ledger /data/kervix/keys; sync"
$Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
for _ in $(seq 1 30); do $C --timeout 2000 $WORLD '{"op":"hello"}' 2>/dev/null | grep -q '"role":"world"' && break; sleep 1; done

echo "== four gateways, each under its own type, uid and priority"
for spec in "agent $AGENT agentgw_t 400 10" "hmi $HMI hmigw_t 401 30" "observer $OBS obsgw_t 402 5" "world $WORLD worldgw_t 403 5"; do
  set -- $spec
  o=$($C $2 '{"op":"hello","id":"h"}' || true)
  has "$o" "\"role\":\"$1\"" && has "$o" "\"type\":\"$3\"" && has "$o" "\"uid\":$4," && has "$o" "\"prio\":$5," \
    && pass "$1 gateway on :$2 runs as $3, uid $4, priority $5" || bad "$1 hello: $o"
done

echo "== agent: propose -> grant -> execute, over the network"
$C $WORLD '{"op":"sim","cmd":"scenario park"}' >/dev/null
o=$($C $AGENT '{"op":"propose","id":"p1","action":"body.door.unlock","actor":"agent:cabin-copilot","params":{"door":"front_left"},"exec":true}')
gid=$(echo "$o" | sed -n 's/.*"kind":"decision".*"grant_id":"\([0-9a-f]*\)".*/\1/p')
has "$o" '"kind":"decision".*"verdict":"ALLOW"' && has "$o" '"kind":"execution".*"result":"EXECUTED"' && [ -n "$gid" ] \
  && pass "body.door.unlock: ALLOW -> EXECUTED (grant $gid stays on the vehicle; the host only sees its id)" || bad "propose/exec: $o"
has "$o" '"intent":{"action":"body.door.unlock","actor":"agent:cabin-copilot","intent_id":"[0-9a-f-]\{36\}","params":{"door":"front_left"}}' \
  && pass "decision echoes the canonical intent (gateway-generated UUIDv4 intent id)" || bad "intent echo: $o"
o=$($C $AGENT "{\"op\":\"execute\",\"id\":\"x\",\"grant_id\":\"$gid\"}")
has "$o" '"result":"REFUSED","reason":"GRANT_SPENT"' && pass "replayed grant: forwarded, refused by the authority (GRANT_SPENT)" || bad "replay: $o"
o=$($C $AGENT '{"op":"execute","id":"x","grant_id":"00000000000000000000000000000000"}')
has "$o" 'unknown grant_id' && pass "a grant the gateway never held cannot be presented" || bad "unknown grant: $o"
o=$($C $AGENT '{"op":"state","id":"s"}')
has "$o" '"kind":"state".*"available":true' && has "$o" '"plausible":true' && has "$o" '"speed_dkph":0' \
  && pass "agent can read vehicle state (read-only shm)" || bad "state: $o"

echo "== the vehicle moves: BLOCK"
$C $WORLD '{"op":"sim","cmd":"scenario highway"}' >/dev/null
for _ in $(seq 1 30); do $C $AGENT '{"op":"state","id":"s"}' | grep -q '"speed_dkph":[1-9][0-9][0-9]' && break; sleep 1; done
o=$($C $AGENT "{\"op\":\"propose\",\"id\":\"p2\",\"action\":\"ota.ecu.flash\",\"params\":{\"ecu\":\"brake\",\"image_digest\":\"$D\"},\"exec\":true}")
has "$o" '"verdict":"BLOCK","reason":"R156_NOT_SAFE_STATE"' && has "$o" '"done":true' && ! has "$o" '"kind":"execution"' \
  && pass "ota.ecu.flash at speed: BLOCK R156_NOT_SAFE_STATE, nothing executed" || bad "block: $o"

echo "== human oversight over the network: escalate -> HMI push -> approve -> agent executes"
$C $WORLD '{"op":"sim","cmd":"scenario park"}' >/dev/null
for _ in $(seq 1 40); do $C $AGENT '{"op":"state","id":"s"}' | grep -q '"speed_dkph":0,"gear":0,"park_brake":1' && break; sleep 1; done
$C --listen 6000 $HMI > build/kxgw-hmi.out 2>&1 &   # an HMI that only listens to pushes
hp=$!
sleep 1
$C $AGENT "{\"op\":\"propose\",\"id\":\"ota\",\"action\":\"ota.ecu.flash\",\"params\":{\"ecu\":\"brake\",\"image_digest\":\"$D\"},\"exec\":true,\"await\":true}" > build/kxgw-agent.out 2>&1 &
ap=$!
eid=''
for _ in $(seq 1 20); do
  eid=$($C $HMI '{"op":"escalations","id":"l"}' | sed -n 's/.*"id":"l".*"items":\[{"escalation_id":\([0-9]*\).*/\1/p')
  [ -n "$eid" ] && break; sleep 0.3
done
o=$($C $HMI "{\"op\":\"resolve\",\"id\":\"r\",\"escalation_id\":${eid:-0},\"approve\":true,\"approver\":\"hmi:driver-seat\"}")
has "$o" '"kind":"resolved".*"approve":true' && pass "HMI approves escalation #$eid" || bad "resolve: $o"
wait $ap || true
wait $hp || true
o=$(cat build/kxgw-agent.out)
has "$o" '"kind":"decision".*"verdict":"ESCALATE".*"reason":"DRIVER_CONSENT".*"done":false' \
  && has "$o" '"kind":"resolution".*"verdict":"ALLOW".*"reason":"HUMAN_APPROVED"' && has "$o" '"kind":"execution".*"result":"EXECUTED"' \
  && pass "agent: ESCALATE (awaiting, not done) -> ALLOW HUMAN_APPROVED -> EXECUTED" || bad "await: $o"
o=$(cat build/kxgw-hmi.out)
has "$o" "\"kind\":\"escalations\".*\"escalation_id\":$eid.*\"action\":\"ota.ecu.flash\"" && has "$o" '"kind":"escalations","available":true,"items":\[\]' \
  && pass "HMI was PUSHED the escalation (kervixd doorbell, no polling) and its removal" || bad "push: $o"

echo "== least privilege: each role only has its own operations"
o=$($C $AGENT '{"op":"resolve","id":"r","escalation_id":1,"approve":true}')
has "$o" "not available on the agent gateway" && pass "agent gateway cannot resolve escalations" || bad "agent resolve: $o"
o=$($C $OBS '{"op":"propose","id":"p","action":"light.hazard.set","params":{"on":true}}')
has "$o" "not available on the observer gateway" && pass "observer gateway cannot propose" || bad "obs propose: $o"
o=$($C $WORLD '{"op":"propose","id":"p","action":"light.hazard.set","params":{"on":true}}')
has "$o" "not available on the world gateway" && pass "world gateway cannot propose" || bad "world propose: $o"
# below the gateway: even a compromised observer/world process has no channel to the authority
o=$($Q ssh "on -T obsgw_t -u 402:402 cat /dev/kervix/intent; on -T worldgw_t -u 403:403 cat /dev/kervix/intent; on -T obsgw_t -u 402:402 cat /dev/kervix/stats | head -1; true" 2>&1)
[ "$(echo "$o" | grep -c '/dev/kervix/intent: Operation not permitted')" = 2 ] && has "$o" "^kervixd  uptime" \
  && pass "kernel: obsgw_t / worldgw_t cannot even connect to /dev/kervix/intent; obsgw_t reads stats (kx_obs_ch_t)" || bad "kernel confinement: $o"

echo "== observer: telemetry stream + stats"
o=$($C --listen 2000 $OBS '{"op":"subscribe","id":"s","hz":20}')
n=$(echo "$o" | grep -c '"kind":"telemetry"' || true)
[ "$n" -ge 20 ] && has "$o" '"kind":"stats","text":\["kervixd  uptime' && pass "observer streams telemetry ($n samples in ~2 s at 20 Hz) and stats" || bad "observer ($n): $(echo "$o" | head -3)"

echo "== hostile input"
big=$(head -c 5000 /dev/zero | tr '\0' 'a')
o=$($C --raw $AGENT 'not json' '{"op":"propose","action":"x","admin":true}' "{\"op\":\"sim\",\"cmd\":\"$big\"}" '{"op":"hello","id":"caf\u00e9"}' '{"op":"hello","id":"café"}' '{"op":"hello","id":"still-alive"}')
has "$o" '"error":"expected a JSON object"' && has "$o" '"error":"unknown key"' && has "$o" '"error":"line too long' \
  && has "$o" 'unsupported string escape' && has "$o" 'non-ASCII' && has "$o" '"id":"still-alive"' \
  && pass "malformed / unknown-key / 5000-byte / \\u-escaped / UTF-8 lines refused; same connection still served" || bad "hostile: $o"
o=$($C $WORLD '{"op":"sim","id":"w","cmd":"spoof speed_dkph 0"}' '{"op":"sim","id":"w2","cmd":"spoof off"}')
has "$o" '"kind":"sim"' && pass "world gateway drives the simulator (and only the simulator)" || bad "sim: $o"

echo "== the authority restarts under the gateways"
$Q ssh "slay -9 -f kervixd; true"
sleep 0.2
o=$($C $AGENT '{"op":"propose","id":"d","action":"light.hazard.set","params":{"on":true}}' || true)
for _ in $(seq 1 30); do $Q ssh 'grep -c "kervixd: ready" /tmp/kervixd.log' | grep -q 2 && break; sleep 0.5; done
o2=$($C $AGENT '{"op":"propose","id":"d2","action":"light.hazard.set","params":{"on":true},"exec":true}')
{ has "$o" 'authority unavailable' || has "$o" '"verdict"'; } && has "$o2" '"result":"EXECUTED"' \
  && pass "gateway survives a kervixd restart; proposals work again with no gateway restart" || bad "restart: $o / $o2"

echo "== nothing was refused that should not be; the dossier verifies"
# (the two refusals the kernel-confinement probe above provoked on purpose are expected)
o=$($Q ssh "slog2info | grep secpolgenerate | grep -E 'type:(vsim|kervix|actuator|agentgw|hmigw|operator|supervisor|obsgw|worldgw)' | grep -v 'cat (pid:[0-9]* type:[a-z]*gw_t) failed to use ability channel_connect:kx_agent_ch_t' || true")
[ -z "$o" ] && pass "no secpol denials for any Kervix type (gateways included), besides the probe's two" || bad "denials: $o"
$Q ssh "rm -rf /tmp/dossier; on -T operator_t /system/bin/kervix/kxctl dossier export /tmp/dossier >/dev/null"
rm -rf build/kxgw-dossier
scp -q -O -r -i vm/ssh/kervix_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@127.0.0.1:/tmp/dossier build/kxgw-dossier
o=$(node host/verify/kervix-verify.mjs build/kxgw-dossier || true)
has "$o" "^VERIFIED" && pass "dossier of the networked session VERIFIED offline (signatures, chain, replay)" || bad "verify: $o"

[ $fail -eq 0 ] && echo "KXGW RESULT: PASS" || { echo "KXGW RESULT: FAIL"; exit 1; }
