#!/usr/bin/env bash
# Signed policy bundles on QNX 8.0 (QEMU), every Kervix type restricted:
# compile on the host, sign as author + a DIFFERENT approver, upload over the
# operator-only admin channel, verified on the vehicle with qcrypto Ed25519,
# activated atomically, recorded in the signed ledger, persisted across a
# crash, and replayed offline under the policy each decision records.
# Usage: tests/target/policy.sh   (make target-policy)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
Q=scripts/qemu.sh
fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
has()  { echo "$1" | grep -q -- "$2"; }
. tests/target/secpol-lib.sh
KP="node host/kxpolicy/src/main.ts"
W=build/policy-test
OP='on -T operator_t /system/bin/kervix/kxctl'
AG='on -T agentgw_t -u 400:400 /system/bin/kervix/kxctl'

echo "== build image: open secpol, Kervix types restricted"
make -s target-x86_64 >/dev/null
$Q stop >/dev/null || true
KX_SNIPPETS=target/image/snippets \
KX_MKQNXIMAGE_EXTRA="--secpol=open --policy=/work/target/secpol/kervix.secpol --secure-procfs=yes" $Q image >/dev/null
$Q start >/dev/null && $Q wait 180 >/dev/null
$Q ssh "for t in $KX_TYPES; do grep -qx \"type \$t restricted\" /data/var/secpol/config || echo \"type \$t restricted\" >> /data/var/secpol/config; done; rm -rf /data/kervix/ledger /data/kervix/keys /data/kervix/policy; sync"
$Q stop >/dev/null; $Q start >/dev/null; $Q wait 180 >/dev/null
for _ in $(seq 1 40); do $Q ssh 'grep -q "kervixd: ready" /tmp/kervixd.log' 2>/dev/null && break; sleep 0.5; done

echo "== host: keys, a changed policy, bundles (good and bad)"
rm -rf $W && mkdir -p $W
for k in author approver stranger; do $KP keygen $W/$k --role $([ $k = approver ] && echo approver || echo author) | tail -1 | sed 's/^ *//' > $W/$k.trust; done
cat $W/author.trust $W/approver.trust > $W/trust
# v1.1.0: the cabin may no longer be set above 26.0 C
sed -e 's/^version: 1.0.0/version: 1.1.0/' \
    -e 's/- { id: climate-any, action: cabin.climate.set, verdict: ALLOW, reason: OK }/- { id: climate-any, action: cabin.climate.set, when: [ param.temp_dc <= 260 ], verdict: ALLOW, reason: OK }/' \
    policies/default.yaml > $W/strict.yaml
grep -q "param.temp_dc <= 260" $W/strict.yaml || { echo "could not derive the test policy"; exit 1; }
$KP author $W/strict.yaml --key $W/author.key -o $W/author-only.kxp >/dev/null
cp $W/author-only.kxp $W/good.kxp && $KP approve $W/good.kxp --key $W/approver.key >/dev/null
cp $W/author-only.kxp $W/untrusted.kxp && $KP approve $W/untrusted.kxp --key $W/stranger.key >/dev/null
node -e 'const fs=require("fs");const b=fs.readFileSync(process.argv[1]);b[200]^=1;fs.writeFileSync(process.argv[2],b)' $W/good.kxp $W/tampered.kxp
head -c 300 /dev/urandom > $W/garbage.kxp
o=$($KP verify $W/good.kxp --trust $W/trust)
newhash=$(echo "$o" | sed -n 's/^policy hash (what the vehicle will record): //p')
has "$o" "ACCEPTED" && pass "host: bundle signed by author + a different approver, accepted by kxpolicy verify (${newhash:0:23}…)" || bad "host verify: $o"
$Q ssh "mkdir -p /data/kervix/policy /tmp/kxp" && $Q scp $W/*.kxp /tmp/kxp/ >/dev/null && $Q scp $W/trust /data/kervix/policy/trust >/dev/null

echo "== before: the built-in policy"
o=$($Q ssh "$OP policy status; $AG propose --exec cabin.climate.set temp_dc=265" 2>&1 || true)
has "$o" "source built-in" && has "$o" "ALLOW    cabin.climate.set" && pass "built-in policy active; cabin 26.5 C -> ALLOW" || bad "before: $o"

echo "== the vehicle refuses what it must"
for spec in "author-only MISSING_ROLE" "untrusted UNTRUSTED" "tampered BAD_SIGNATURE" "garbage malformed"; do
  set -- $spec
  o=$($Q ssh "$OP policy load /tmp/kxp/$1.kxp" 2>&1 || true)
  has "$o" "REFUSED  $2" && has "$o" "source built-in" && pass "$1 bundle refused on the vehicle ($2); built-in policy stays" || bad "$1: $o"
done
o=$($Q ssh "$AG policy status; on -T hmigw_t /system/bin/kervix/kxctl policy status; true" 2>&1)
[ "$(echo "$o" | grep -c '/dev/kervix/policy: Operation not permitted')" = 2 ] \
  && pass "kernel: agent (agentgw_t) and HMI (hmigw_t) cannot even connect to the policy channel" || bad "admin channel: $o"

echo "== never while something is in flight"
$Q ssh "$AG propose telematics.location.share recipient=fleet_operator duration_s=600 >/dev/null; true"
o=$($Q ssh "$OP policy load /tmp/kxp/good.kxp" 2>&1 || true)
has "$o" "REFUSED  grants or escalations in flight" && pass "pending escalation: activation refused (EBUSY), retry later" || bad "busy: $o"
$Q ssh "id=\$($OP escalations | sed -n 's/^#\([0-9]*\) .*/\1/p' | head -1); on -T hmigw_t /system/bin/kervix/kxctl deny \$id >/dev/null"

echo "== activate"
o=$($Q ssh "$OP policy load /tmp/kxp/good.kxp" 2>&1 || true)
has "$o" "^ACTIVATED" && has "$o" "kervix-default v1.1.0" && has "$o" "${newhash#sha256:}" && has "$o" "source bundle author:author approver:approver" \
  && pass "signed bundle ACTIVATED: v1.1.0, the hash the host computed, author + approver recorded" || bad "activate: $o"
o=$($Q ssh "$AG propose --exec cabin.climate.set temp_dc=265; $AG propose --exec cabin.climate.set temp_dc=225" 2>&1 || true)
has "$o" "BLOCK    cabin.climate.set  rule=-  reason=DEFAULT_DENY" && has "$o" "ALLOW    cabin.climate.set  rule=climate-any" \
  && pass "the new policy decides at once: 26.5 C -> BLOCK, 22.5 C -> ALLOW" || bad "after: $o"
o=$($Q ssh "$OP policy load /tmp/kxp/good.kxp" 2>&1 || true)
has "$o" "REFUSED  this policy is already active" && pass "re-activating the same policy: refused (EALREADY)" || bad "again: $o"

echo "== it survives a crash; withdrawing trust falls back to the built-in policy"
$Q ssh "slay -9 -f kervixd; true"
for _ in $(seq 1 40); do $Q ssh "grep -c 'kervixd: ready' /tmp/kervixd.log" | grep -q 2 && break; sleep 0.5; done
o=$($Q ssh "$OP policy status; grep 'policy from signed bundle' /tmp/kervixd.log" 2>&1 || true)
has "$o" "kervix-default v1.1.0" && has "$o" "policy from signed bundle" && pass "kill -9 + supervised restart: the signed policy is re-verified and back in force" || bad "persist: $o"
$Q ssh "cp /data/kervix/policy/trust /tmp/kxp/trust.saved; grep approver /tmp/kxp/trust.saved > /data/kervix/policy/trust; slay -9 -f kervixd; true"
for _ in $(seq 1 40); do $Q ssh "grep -c 'kervixd: ready' /tmp/kervixd.log" | grep -q 3 && break; sleep 0.5; done
o=$($Q ssh "$OP policy status; grep 'bundle REJECTED' /tmp/kervixd.log" 2>&1 || true)
has "$o" "source built-in" && has "$o" "REJECTED (UNTRUSTED)" && pass "author key withdrawn from the trust file: bundle rejected at start, built-in policy in force" || bad "untrust: $o"
$Q ssh "cp /tmp/kxp/trust.saved /data/kervix/policy/trust; slay -9 -f kervixd; true"
for _ in $(seq 1 40); do $Q ssh "grep -c 'kervixd: ready' /tmp/kervixd.log" | grep -q 4 && break; sleep 0.5; done

echo "== the dossier: signed policies shipped, every decision replayed under its own policy"
$Q ssh "rm -rf /tmp/dossier; $OP dossier export /tmp/dossier >/dev/null"
rm -rf build/policy-dossier
scp -q -O -r -i vm/ssh/kervix_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@127.0.0.1:/tmp/dossier build/policy-dossier
o=$(node host/verify/kervix-verify.mjs build/policy-dossier || true)
echo "$o" | grep -E "policies|replay|VERIFIED" | sed 's/^/INFO  /'
has "$o" "^VERIFIED" && has "$o" "1 signed bundle" && has "$o" "under 2 policies" && grep -q '"event":"policy_activated"' build/policy-dossier/capsules.jsonl \
  && pass "dossier VERIFIED offline: bundle signatures checked, decisions replayed under both policies" || bad "verify: $o"

o=$($Q ssh "slog2info | grep secpolgenerate | grep -E 'type:(vsim|kervix|actuator|agentgw|hmigw|operator|supervisor|obsgw|worldgw)' | grep -v 'kx_admin_ch_t' || true")
[ -z "$o" ] && pass "no secpol denials besides the two admin-channel probes" || bad "denials: $o"
[ $fail -eq 0 ] && echo "POLICY RESULT: PASS" || { echo "POLICY RESULT: FAIL"; exit 1; }
