#!/usr/bin/env bash
# Build host/verify/kxcore.wasm from the unmodified libkxcore sources.
# Uses the local clang if it can target wasm32 (Linux CI), else a small
# native-arch Docker image (macOS).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
OUT=host/verify/kxcore.wasm
SRC="wasm/kxw.c wasm/libc_shim.c target/libkxcore/src/catalog_gen.c target/libkxcore/src/policy.c \
     target/libkxcore/src/policy_default.c target/libkxcore/src/policy_load.c target/libkxcore/src/sha256.c target/libkxcore/src/jcs.c \
     target/libkxcore/src/intent.c"
FLAGS="--target=wasm32 -O2 -std=c11 -ffreestanding -nostdlib -fvisibility=hidden -Wall -Wextra -Werror \
       -Wno-missing-field-initializers -Iwasm/include -Itarget/include \
       -Wl,--no-entry -Wl,--export-memory -Wl,--strip-all -Wl,-z,stack-size=65536"
if clang --print-targets 2>/dev/null | grep -q wasm32 && command -v wasm-ld >/dev/null; then
  clang $FLAGS -o $OUT $SRC
else
  docker image inspect kervix/wasm-build:1 >/dev/null 2>&1 || docker build -q -t kervix/wasm-build:1 -f docker/wasm.Dockerfile docker >/dev/null
  docker run --rm -v "$PWD:/work" -w /work kervix/wasm-build:1 bash -c "clang $FLAGS -o $OUT $SRC"
fi
echo "built $OUT ($(wc -c < $OUT | tr -d ' ') bytes)"
