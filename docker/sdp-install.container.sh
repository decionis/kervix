#!/usr/bin/env bash
# Runs INSIDE the qnx-build container (started by docker/install-sdp.sh).
# Installs QNX SDP 8.0 into /root/qnx800 on the kervix-qnx-home volume.
set -euo pipefail
: "${QSC_RUN:?path to qnx-setup-*-linux.run}"
DEST=/root/qnx800
QSC_DIR=/root/qnx-software-center

if [ -f "$DEST/qnxsdp-env.sh" ]; then
  echo "SDP already installed at $DEST (volume kervix-qnx-home). To reinstall: docker volume rm kervix-qnx-home"
  exit 0
fi

echo "== Unpacking QNX Software Center (no GUI)…"
mkdir -p "$QSC_DIR"
sh "$QSC_RUN" --tar xf -C "$QSC_DIR"
CLT=$(find "$QSC_DIR" -maxdepth 3 -name qnxsoftwarecenter_clt -type f | head -1)
[ -n "$CLT" ] || { echo "qnxsoftwarecenter_clt not found after extraction"; ls -la "$QSC_DIR"; exit 1; }

echo
echo "== myQNX credentials (used for this run only; not stored by this script)"
read -r  -p "myQNX email: " QNX_USER
read -rs -p "myQNX password: " QNX_PASS; echo
read -r  -p "License key (QNX Everywhere; leave empty if already deployed to your account): " QNX_KEY
auth=(-myqnx.user "$QNX_USER" -myqnx.password "$QNX_PASS")

if [ -n "$QNX_KEY" ]; then
  echo "== Adding license key…"
  # The tool echoes the key; mask it.
  "$CLT" "${auth[@]}" -addLicenseKey "$QNX_KEY" 2>&1 | sed -E 's/[A-Z0-9]{4}(-[A-Z0-9]{4}){4}/<license key>/g'
fi

echo "== Installing SDP 8.0 baseline into $DEST (several GB; slow under x86 emulation, ~20–60 min)…"
"$CLT" "${auth[@]}" -cleanInstall -mirrorBaseline qnx800 -installBaseline com.qnx.qnx800 -destination "$DEST"
unset QNX_PASS

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
