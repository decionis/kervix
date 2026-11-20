#!/usr/bin/env bash
# J5 "crash, fail closed, recover" on QNX 8.0 (QEMU), with every Kervix type
# enforced (--secpol=open image, Kervix types restricted, as tests/target/secpol.sh):
#   - kx-supervisor (supervisor_t) starts kervixd as kervix_t at boot
#   - kill -9 the authority: actuation is locked while it is gone
#   - the supervisor restarts it; old grants are dead (new per-boot key)
#   - the new epoch capsule records why it began; the dossier verifies offline
#   - a crash loop makes the supervisor give up: the authority stays DOWN
# Usage: tests/target/supervisor.sh   (make target-supervisor)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
has()  { echo "$1" | grep -q -- "$2"; }
. tests/target/secpol-lib.sh
AG='on -T agentgw_t -u 400:400 /system/bin/kervix/kxctl'
OP='on -T operator_t /system/bin/kervix/kxctl'
kpid() { $Q ssh 'pidin -p kervixd -F "%a" 2>/dev/null | tail -1 | tr -d " "'; }
wait_ready() { # $1 = number of "ready" lines expected in the supervisor log
  for _ in $(seq 1 60); do
    [ "$($Q ssh 'grep -c "kervixd: ready" /tmp/kervixd.log' || true)" -ge "$1" ] && return 0; sleep 0.5
  done; return 1
}

echo "== build image: open secpol, Kervix types restricted, supervisor at boot"
make -s target-x86_64 >/dev/null
$Q stop >/dev/null || true
KX_SNIPPETS=target/image/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/target/secpol/kervix.secpol --secure-procfs=yes" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null
$Q ssh "for t in $KX_TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; rm -rf /data/kervix/ledger /data/kervix/keys; sync"
$Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
wait_ready 1 || bad "kervixd never became ready under the supervisor"

o=$($Q ssh 'pidin -f an_ | grep -E "kx-supervisor|kervixd"; cat /tmp/kervixd.log')
has "$o" "kx-supervisor .*supervisor_t" && has "$o" "kervixd .*kervix_run_t" && has "$o" "kervixd ready in" \
  && pass "boot: kx-supervisor (supervisor_t) started kervixd (kervix_t -> kervix_run_t)" || bad "boot: $o"

echo "== crash while the supervisor is held: actuation is locked"
p1=$(kpid)
# the saved-grant file is a test device; agentgw_t has no filesystem rights, so the operator holds it
o=$($Q ssh "$AG propose --exec body.door.unlock door=front_left; $OP propose --save-grant /tmp/g-old.bin cabin.climate.set temp_dc=212" 2>&1 || true)
has "$o" "execute  EXECUTED" && pass "before the crash: agent proposes and actuates" || bad "pre-crash: $o"
$Q ssh "slay -s SIGSTOP -f kx-supervisor; slay -9 -f kervixd; sleep 0.5"
o=$($Q ssh "$AG propose --exec body.door.unlock door=front_left; $OP execute --grant /tmp/g-old.bin; true" 2>&1)
has "$o" "is kervixd running" && pass "authority down: no proposal possible" || bad "down propose: $o"
has "$o" "REFUSED   AUTHORITY_UNAVAILABLE" && pass "authority down: actuator refuses a valid grant (AUTHORITY_UNAVAILABLE)" || bad "down exec: $o"

echo "== the supervisor restarts it"
$Q ssh "slay -s SIGCONT -f kx-supervisor; true"   # slay exits with the number of processes signalled
wait_ready 2 || bad "no restart"
p2=$(kpid)
o=$($Q ssh 'cat /tmp/kervixd.log')
echo "$o" | grep "kx-supervisor:" | sed 's/^/INFO  /'
has "$o" "ended (SIGKILL)" && has "$o" "authority back in .* after SIGKILL (restart #1" && [ -n "$p2" ] && [ "$p1" != "$p2" ] \
  && pass "kill -9 detected; new kervixd (pid $p1 -> $p2), restart #1 recorded" || bad "restart: $o"
o=$($Q ssh "$OP execute --grant /tmp/g-old.bin; $AG propose --exec body.door.unlock door=rear_left; true" 2>&1)
has "$o" "REFUSED   GRANT_MAC" && pass "a grant from before the crash is dead (new per-boot key)" || bad "old grant: $o"
has "$o" "execute  EXECUTED" && pass "after the restart: proposals and actuation work again" || bad "post-restart: $o"

echo "== restart latency with the supervisor running: kill -9 -> ready"
$Q ssh "slay -9 -f kervixd; true"
wait_ready 3 || bad "no second restart"
lat=$($Q ssh 'grep "restart #2" /tmp/kervixd.log' | sed -n 's/.*back in \([0-9.]*\) ms.*/\1/p')
[ -n "$lat" ] && pass "restart #2: authority back in $lat ms (QEMU/TCG, emulated: not representative; RPi4 target <= 200 ms)" || bad "latency"

echo "== the ledger explains the gap (offline verification on the host)"
$Q ssh "rm -rf /tmp/dossier; $OP dossier export /tmp/dossier >/dev/null"
rm -rf build/sv-dossier
scp -q -O -r -i vm/ssh/kervix_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@127.0.0.1:/tmp/dossier build/sv-dossier
o=$(node host/verify/kervix-verify.mjs build/sv-dossier || true)
has "$o" "^VERIFIED" && has "$o" "continuous, 3 epoch(s)" && pass "dossier VERIFIED offline: chain continuous across 3 epochs" || bad "verify: $o"
r=$(grep -o '"recovery":{[^}]*}' build/sv-dossier/capsules.jsonl | tr '\n' ' ')
[ "$r" = '"recovery":{"cause":"SIGKILL","restart":1} "recovery":{"cause":"SIGKILL","restart":2} ' ] \
  && pass "epoch capsules record each restart and its cause: $r" || bad "recovery evidence: $r"

echo "== crash loop: the supervisor gives up, the vehicle stays locked"
# kill every new instance as soon as it is ready, until the supervisor gives up
n=$($Q ssh 'grep -c "kervixd: ready" /tmp/kervixd.log')
for _ in $(seq 1 10); do
  $Q ssh "slay -9 -f kervixd" >/dev/null 2>&1 || true
  sleep 0.5
  $Q ssh 'grep -q "crash loop" /tmp/kervixd.log' && break
  n=$((n + 1)); wait_ready "$n" || true
done
sleep 1
o=$($Q ssh "cat /tmp/kervixd.log; echo SUP=\$(pidin -p kx-supervisor -F '%N' | tail -n +2 | tr -d ' '); echo KX=\$(pidin -p kervixd -F '%N' | tail -n +2 | tr -d ' '); $AG propose --exec body.door.unlock door=front_left; true" 2>&1)
has "$o" "crash loop (5 restarts in 60 s): NOT restarting" && has "$o" "^SUP=$" && has "$o" "^KX=$" \
  && pass "6th crash in 60 s: supervisor stops restarting and exits; no kervixd running (fault not hidden)" || bad "crash loop: $(echo "$o" | grep -E 'crash loop|^SUP=|^KX=')"
has "$o" "is kervixd running" && pass "authority stays DOWN: actuation locked (fail closed)" || bad "after give-up: $o"

o=$($Q ssh "slog2info | grep secpolgenerate | grep -E 'type:(vsim|kervix|actuator|agentgw|hmigw|operator|supervisor)' || true")
[ -z "$o" ] && pass "no secpol denials for any Kervix type (supervisor included)" || bad "denials: $o"

[ $fail -eq 0 ] && echo "SUPERVISOR RESULT: PASS" || { echo "SUPERVISOR RESULT: FAIL"; exit 1; }
