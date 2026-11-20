#!/usr/bin/env bash
# Runs INSIDE the qnx-build container (started by docker/install-sdp.sh).
# Installs QNX SDP 8.0 into /root/qnx800 on the kervix-qnx-home volume.
set -euo pipefail
: "${QSC_RUN:?path to qnx-setup-*-linux.run}"
DEST=/root/qnx800
QSC_DIR=/root/qnx-software-center

if [ -f "$DEST/qnxsdp-env.sh" ]; then
  echo "SDP already installed at $DEST (volume kervix-qnx-home). Keep the volume: it also holds your QNX license activation."
  exit 0
fi

echo "== Unpacking QNX Software Center (no GUI)…"
mkdir -p "$QSC_DIR"
sh "$QSC_RUN" --tar xf -C "$QSC_DIR"
CLT=$(find "$QSC_DIR" -maxdepth 3 -name qnxsoftwarecenter_clt -type f | head -1)
[ -n "$CLT" ] || { echo "qnxsoftwarecenter_clt not found after extraction"; ls -la "$QSC_DIR"; exit 1; }

mask_license_keys() {
  sed -uE 's/[[:alnum:]]{4}(-[[:alnum:]]{4}){4}/<license key>/g'
}

run_qsc() {
  "$CLT" "${auth[@]}" "$@" 2>&1 | mask_license_keys
}

echo
echo "== myQNX credentials (used for this run only; not stored by this script)"
set +x
read -r  -p "myQNX email: " QNX_USER
read -rs -p "myQNX password: " QNX_PASS; echo
read -rs -p "SDP 8.0 license key (leave empty to retrieve a single deployed key from myQNX): " QNX_KEY; echo
# QSC logs passwords supplied directly as command-line arguments. Its options
# file avoids that logging; /dev/shm keeps this temporary file in container RAM.
auth_file=$(mktemp /dev/shm/kervix-qnx-auth.XXXXXX)
trap 'rm -f -- "$auth_file"; unset QNX_PASS QNX_KEY auth license_report deployed_keys' EXIT
printf '%s\n' '-myqnx.user' "$QNX_USER" '-myqnx.password' "$QNX_PASS" > "$auth_file"
auth=("@$auth_file")
unset QNX_PASS

if [ -z "$QNX_KEY" ]; then
  echo "== Retrieving deployed licenses from myQNX…"
  if ! license_report=$("$CLT" "${auth[@]}" -syncLicenseKeys -listLicenseKeys 2>&1); then
    printf '%s\n' "$license_report" | mask_license_keys >&2
    exit 1
  fi
  mapfile -t deployed_keys < <(
    printf '%s\n' "$license_report" | grep -owE '[A-Z0-9]{4}(-[A-Z0-9]{4}){4}' | sort -u || true
  )
  if [ "${#deployed_keys[@]}" -eq 1 ]; then
    QNX_KEY=${deployed_keys[0]}
  else
    echo "Found ${#deployed_keys[@]} deployed keys; enter the specific SDP 8.0 key from myQNX."
    read -rs -p "SDP 8.0 license key: " QNX_KEY; echo
  fi
fi
[ -n "$QNX_KEY" ] || { echo "An SDP 8.0 license key is required for activation." >&2; exit 2; }

# Deployment to an account and activation on this host are separate steps.
# QSC 2.0.4 documents -addLicenseKey as both adding and activating a key.
echo "== Activating the selected SDP license in this Docker volume…"
run_qsc -addLicenseKey "$QNX_KEY"

echo "== Installing SDP 8.0 baseline into $DEST (several GB; slow under x86 emulation, ~20–60 min)…"
run_qsc -destination "$DEST" -cleanInstall -mirrorBaseline qnx800 -installBaseline com.qnx.qnx800
rm -f -- "$auth_file"
unset QNX_PASS QNX_KEY auth license_report deployed_keys

# shellcheck disable=SC1091
source "$DEST/qnxsdp-env.sh" >/dev/null
echo
echo "== Verification"
echo "QNX_HOST=$QNX_HOST"
echo "QNX_TARGET=$QNX_TARGET"
qcc -V 2>&1 | head -5 || true
command -v mkqnximage || echo "mkqnximage: not found"
ls "$QNX_HOST/usr/bin" | grep -E '^secpol' || echo "secpol tools: not in baseline (S1 will add the package)"
ls "$QNX_TARGET"/usr/include/qcrypto 2>/dev/null | head -3 || true
echo "sdp: done"
