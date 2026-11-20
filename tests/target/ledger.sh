#!/usr/bin/env bash
# M2 signed-ledger acceptance on QNX 8.0 (QEMU) + offline verification on the host.
# Usage: tests/target/ledger.sh   (make target-ledger)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
B=build/qnx-x86_64/target
V="node host/verify/kervix-verify.mjs"
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
has()  { echo "$1" | grep -q -- "$2"; }

make -s target-x86_64 >/dev/null
$Q status | grep -q running || { $Q start >/dev/null; $Q wait 180 >/dev/null; }
$Q ssh 'slay -f vsimd kervixd sdv_actuatord >/dev/null 2>&1; rm -rf /data/kervix/ledger /data/kervix/keys /tmp/dossier*; mkdir -p /data/kervix/bin; cd /data/kervix/bin && rm -f vsimd kervixd sdv_actuatord kxctl'
$Q scp $B/vsimd/vsimd $B/kervixd/kervixd $B/sdv_actuatord/sdv_actuatord $B/kxctl/kxctl /data/kervix/bin/
T() { $Q ssh "cd /data/kervix/bin; $*"; }
K=./kxctl
D=sha256:0101010101010101010101010101010101010101010101010101010101010101
fetch() { rm -rf "build/$2"; scp -q -O -r -i vm/ssh/kervix_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@127.0.0.1:$1" "build/$2"; }
start_kervixd() { T "(./kervixd $* > /tmp/kervixd.log 2>&1 &); sleep 1.5"; }

echo "== first boot"
T '(./vsimd > /tmp/vsimd.log 2>&1 &); (./sdv_actuatord > /tmp/act.log 2>&1 &)'
start_kervixd
o=$(T 'cat /tmp/kervixd.log; ls -l /data/kervix/keys/vehicle.key')
has "$o" "generated new vehicle key" && has "$o" "^-r-------- " && pass "vehicle Ed25519 key generated on first boot, mode 0400" || bad "key: $o"
kid1=$(T 'cat /data/kervix/keys/vehicle.jwk.json' | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')

echo "== lifecycle"
T "$K propose --exec body.door.unlock door=front_left >/dev/null; $K propose --replay cabin.climate.set temp_dc=230 >/dev/null; \
   $K propose --forge light.hazard.set on=1 >/dev/null; $K propose --save-grant /tmp/g cabin.climate.set temp_dc=200 >/dev/null; \
   $K sim scenario highway >/dev/null; sleep 3; $K propose ota.ecu.flash ecu=brake image_digest=$D >/dev/null; \
   $K propose body.door.unlock door=rear_left >/dev/null; $K sim scenario park >/dev/null; sleep 12; \
   $K propose --await --exec ota.ecu.flash ecu=brake image_digest=$D > /tmp/o.out 2>&1 & p=\$!; sleep 1; \
   id=\$($K escalations | sed -n 's/^#\([0-9]*\) .*/\1/p' | head -1); $K approve \$id >/dev/null; wait \$p; true" || true
sleep 1
T "$K dossier export /tmp/dossier >/dev/null"
fetch /tmp/dossier dossier
o=$($V build/dossier || true); echo "$o" | sed 's/^/INFO  /'
has "$o" "^VERIFIED" && pass "dossier signed on QNX verifies offline on the host (kervix-verify)" || bad "verify"
n=$(echo "$o" | sed -n 's/.*replay  *\([0-9]*\)\/\([0-9]*\) decision.*/\1 \2/p')
set -- $n; [ -n "${1:-}" ] && [ "$1" = "$2" ] && [ "$1" -gt 0 ] && pass "replay: all $1 decisions reproduced by the vehicle's own policy core (WASM), intent hashes recomputed" || bad "replay: $o"
for e in epoch decision effect grant_refused grant_expired escalation_resolved; do
  has "$o" "$e=" || bad "lifecycle is missing event $e"
done
has "$o" "grant_refused=" && has "$o" "escalation_resolved=1" && pass "lifecycle covers decisions, effects, refusals, expiry and a human approval" || true

echo "== an edited decision that contradicts the policy is caught by replay (see also tests/conformance/liar-dossier.mjs)"
python3 - <<'PY'
import json,shutil,hashlib
shutil.rmtree("build/dl",ignore_errors=True); shutil.copytree("build/dossier","build/dl")
p="build/dl/capsules.jsonl"; lines=open(p).read().splitlines()
for i,l in enumerate(lines):
    c=json.loads(l); k=c["evidence"]["kervix"]
    if k["event"]=="decision" and k["reason"]=="R156_NOT_SAFE_STATE":
        k["verdict"]="ALLOW"; k["reason"]="OK"; lines[i]=json.dumps(c,separators=(",",":")); break
open(p,"w").write("\n".join(lines)+"\n")
PY
o=$($V build/dl || true)
has "$o" "decision does not follow from the policy: verdict: recorded ALLOW, replay BLOCK" && pass "OTA flash at 110 km/h recorded as ALLOW: replay re-derives BLOCK and flags it" || bad "lying authority: $o"

echo "== tampering (each must be detected)"
tamper() { rm -rf build/dt; cp -r build/dossier build/dt; "$@"; }
refresh_manifest() { # an attacker who also rewrites the manifest hashes
  python3 - "$1" <<'PY'
import hashlib,json,sys,os
d=sys.argv[1]; m=json.load(open(f"{d}/manifest.json"))
for f in m["files"]: m["files"][f]="sha256:"+hashlib.sha256(open(f"{d}/{f}","rb").read()).hexdigest()
n=sum(1 for l in open(f"{d}/capsules.jsonl") if l.strip()); m["records"]=n
open(f"{d}/manifest.json","w").write(json.dumps(m))
PY
}
tamper sed -i '' '2s/"speed_dkph":0/"speed_dkph":1/' build/dt/capsules.jsonl
o=$($V build/dt || true); has "$o" "FAIL \[manifest\] capsules.jsonl" && pass "edited evidence (speed): manifest hash mismatch" || bad "t1 $o"
refresh_manifest build/dt
o=$($V build/dt || true); has "$o" "capsule #2: capsule_id does not match its content: TAMPERED" && pass "...and with a forged manifest: capsule #2 identity TAMPERED" || bad "t2 $o"
tamper sed -i '' '3d' build/dt/capsules.jsonl; sed -i '' '3d' build/dt/envelopes.txt; refresh_manifest build/dt
o=$($V build/dt || true); has "$o" "\[chain\] capsule #3" && pass "deleted record: chain break detected at #3" || bad "t3 $o"
tamper python3 - <<'PY'
import sys
p="build/dt/envelopes.txt"; l=open(p).read().splitlines(); l[1],l[2]=l[2],l[1]; open(p,"w").write("\n".join(l)+"\n")
PY
refresh_manifest build/dt
o=$($V build/dt || true); has "$o" "\[signatures\] capsule #2" && pass "swapped signatures: envelope verification fails" || bad "t4 $o"
tamper python3 - <<'PY'
import base64,json,os
p="build/dt/vehicle.jwk.json"; j=json.load(open(p)); x=bytearray(base64.urlsafe_b64decode(j["keys"][0]["x"]+"=")); x[0]^=1
j["keys"][0]["x"]=base64.urlsafe_b64encode(bytes(x)).decode().rstrip("=")
open(p,"w").write(json.dumps(j))
PY
refresh_manifest build/dt
o=$($V build/dt || true); has "$o" "signed by a key other than the pinned vehicle key" && pass "substituted public key: signatures not from the pinned key" || bad "t5 $o"

echo "== crash + torn write recovery"
T 'slay -9 -f kervixd; sleep 0.3; head -c 100 /dev/urandom >> /data/kervix/ledger/ledger.kxl; sync'
start_kervixd
o=$(T 'cat /tmp/kervixd.log')
has "$o" "quarantined 100 torn byte" && pass "restart after kill -9 + torn write: 100 bytes quarantined, not silently dropped" || bad "recovery: $o"
kid2=$(T 'cat /data/kervix/keys/vehicle.jwk.json' | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p')
[ "$kid1" = "$kid2" ] && pass "same vehicle key after restart ($kid2)" || bad "key changed $kid1 -> $kid2"
T "$K propose --exec cabin.climate.set temp_dc=215 >/dev/null; sleep 0.5; $K dossier export /tmp/dossier2 >/dev/null"
fetch /tmp/dossier2 dossier2
o=$($V build/dossier2 || true)
has "$o" "^VERIFIED" && has "$o" "continuous, 2 epoch(s)" && pass "chain continuous across the crash (2 epochs, epoch_opens)" || bad "post-crash verify: $o"
grep -q '"quarantined_bytes":100' build/dossier2/capsules.jsonl && pass "epoch capsule records quarantined_bytes=100" || bad "quarantined_bytes not recorded"

echo "== K3: no audit, no action (slow storage + flood)"
T 'slay -f kervixd; sleep 0.3'
start_kervixd -R 16 -S 250
o=$(T "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do $K propose cabin.climate.set temp_dc=21\$((i%10)) | head -1; done; $K propose body.door.unlock door=front_left | head -1; $K stats | grep '^ledger'")
has "$o" "LEDGER_PRESSURE" && pass "queue saturated by slow storage: proposals BLOCK LEDGER_PRESSURE (fail closed)" || bad "K3: $o"
sleep 6
o=$(T "$K propose body.door.unlock door=front_left | head -1")
has "$o" "^ALLOW" && pass "once the ledger drains, decisions resume" || bad "resume: $o"
T "sleep 1; $K dossier export /tmp/dossier3 >/dev/null"
fetch /tmp/dossier3 dossier3
o=$($V build/dossier3 || true)
has "$o" "^VERIFIED" && pass "ledger still verifies after back-pressure (every action recorded)" || bad "post-K3 verify: $o"
has "$o" "ledger back-pressure override" && pass "replay accounts for K3 back-pressure decisions" || bad "K3 replay: $o"

T 'slay -f vsimd kervixd sdv_actuatord >/dev/null 2>&1; true'
[ $fail -eq 0 ] && echo "LEDGER RESULT: PASS" || { echo "LEDGER RESULT: FAIL"; exit 1; }
