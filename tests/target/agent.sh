#!/usr/bin/env bash
# The scripted agent (demo scenes 1-3) against QNX 8.0 (QEMU): every verdict is
# decided live by kervixd; the transcripts must still match. Then the signed
# dossier of the session verifies offline and holds the driver's approval.
# Usage: tests/target/agent.sh   (make target-agent)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
. tests/target/gateway-image.sh
PORT=8791
node host/bridge/src/main.ts --listen 127.0.0.1:$PORT > build/agent-bridge.log 2>&1 &
bp=$!
trap 'kill $bp 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -sf http://127.0.0.1:$PORT/api/health | grep -q '"world":{"up":true' && break; sleep 0.2; done
o=$(KX_BRIDGE=http://127.0.0.1:$PORT node host/agent/src/main.ts script scenarios/s1-cold.json scenarios/s2-injection.json scenarios/s3-escalate.json --auto-approve 1500 2>&1 || true)
echo "$o" | sed 's/^/INFO  /'
echo "$o" | grep -q "^PASS  s1-cold: cabin_climate_set ALLOW" && pass "scene 1: climate in city traffic -> ALLOW, executed" || bad "scene 1"
echo "$o" | grep -q "^PASS  s2-injection: ota_ecu_flash BLOCK" && pass "scene 2: injected OTA flash at highway speed -> BLOCK R156_NOT_SAFE_STATE" || bad "scene 2"
echo "$o" | grep -q "^PASS  s3-escalate: ota_ecu_flash ALLOW" && echo "$o" | grep -q '"driver":"approved"' && pass "scene 3: parked + charging -> ESCALATE -> driver approves -> executed" || bad "scene 3"
n=$(curl -sf "http://127.0.0.1:$PORT/api/feed" | grep -o '"kind":"note"' | wc -l | tr -d ' ')
[ "$n" -ge 10 ] && pass "dashboard feed carries the agent's narration ($n notes)" || bad "notes: $n"

Q=scripts/qemu.sh
$Q ssh "rm -rf /tmp/dossier; on -T operator_t /system/bin/kervix/kxctl dossier export /tmp/dossier >/dev/null"
rm -rf build/agent-dossier
scp -q -O -r -i vm/ssh/kervix_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@127.0.0.1:/tmp/dossier build/agent-dossier
o=$(node host/verify/kervix-verify.mjs build/agent-dossier || true)
echo "$o" | grep -q "^VERIFIED" && pass "the session's dossier VERIFIED offline (signatures, chain, replay)" || bad "verify: $o"
grep -q "\"approver\":\"hmi:auto-approve(scripted run)(pid " build/agent-dossier/capsules.jsonl && grep -q '"actor":"agent:cabin-copilot"' build/agent-dossier/capsules.jsonl \
  && pass "signed capsules name the agent (actor) and the human approver" || bad "approver/actor not in capsules"
[ $fail -eq 0 ] && echo "AGENT RESULT: PASS" || { echo "AGENT RESULT: FAIL"; exit 1; }
