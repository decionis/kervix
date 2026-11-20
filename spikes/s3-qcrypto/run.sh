#!/usr/bin/env bash
# Spike S3: qcrypto (openssl-3 plugin) Ed25519 + DRBG on QNX 8.0.
# Reproduces the pinned draft-04 COSE_Sign1 signature byte-for-byte.
# Usage: spikes/s3-qcrypto/run.sh   (any QEMU image built by scripts/qemu.sh)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
make -s target-x86_64 >/dev/null
scripts/qemu.sh status | grep -q running || { scripts/qemu.sh start >/dev/null; scripts/qemu.sh wait 180; }
scripts/qemu.sh ssh 'mkdir -p /data/kervix/s3'
scripts/qemu.sh scp build/qnx-x86_64/spikes/s3-qcrypto/s3_qcrypto /data/kervix/s3/
scripts/qemu.sh ssh '/data/kervix/s3/s3_qcrypto'
