#!/usr/bin/env bash
# host/bridge end to end against QNX 8.0 (QEMU): REST + WebSocket -> kxgw -> kervixd.
# Usage: tests/target/bridge.sh   (make target-bridge)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
. tests/target/gateway-image.sh
node tests/target/bridge-e2e.ts
