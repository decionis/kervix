# Kervix top-level shortcuts. Host targets run natively. QNX targets run in
# the qnx-build container (docker/qnx-build.sh), which works on macOS and Linux.
.PHONY: help host asan wasm test codegen codegen-check spikes target qnx-shell qemu-image qemu-start qemu-stop qemu-ssh target-test target-vsim target-m1 target-escalation target-ledger target-secpol target-secpol-secure secpol-harvest target-supervisor target-kxgw target-bridge target-agent target-selftest target-selftest-secure target-bench target-policy codelab fuzz-wire tsan clean

ARCHES ?= x86_64 aarch64le
KX_CORE_TESTS = libkxcore/tests/test_catalog libkxcore/tests/test_policy libkxcore/tests/test_sha256 \
                libkxcore/tests/test_intent libkxcore/tests/test_grant libkxcore/tests/test_ratelimit libkxcore/tests/test_capsule libkxcore/tests/test_ledger libkxsim/tests/test_sim libkxsim/tests/test_seqlock

help:
	@echo "make host            build libkxcore + host tests (native)"
	@echo "make test            run host unit tests + codegen check + spikes"
	@echo "make asan            host unit tests under AddressSanitizer + UBSan"
	@echo "make wasm            rebuild the replay engine (libkxcore -> WebAssembly)"
	@echo "make tsan            seqlock under ThreadSanitizer"
	@echo "make codegen         regenerate C/TS/tool schemas from catalog/catalog.yaml"
	@echo "make target          build QNX 8.0 binaries for: $(ARCHES) (needs SDP, see docs/setup-macos.md)"
	@echo "make qnx-shell       interactive shell with the QNX SDP environment"
	@echo "make qemu-image      build the QNX 8.0 x86_64 QEMU image (mkqnximage, in the container)"
	@echo "make qemu-start      boot it headless on this machine (ssh on localhost:2222)"
	@echo "make target-test     cross-build, copy and run libkxcore tests ON QNX (QEMU)"
	@echo "make target-vsim     vsimd + kxctl acceptance test on QNX"
	@echo "make target-m1       authority MVP acceptance (propose/grant/redeem/attacks) on QNX"
	@echo "make target-escalation  driver approval / deny / timeout acceptance on QNX"
	@echo "make target-ledger   signed ledger + kervix-verify + tamper + crash recovery on QNX"
	@echo "make target-secpol   every component under an enforced secpol type + kx-rogue red team on QNX"
	@echo "make target-secpol-secure  the same on a --secpol=secure release image (one complete policy)"
	@echo "make secpol-harvest  regenerate target/secpol/system.secpol with secpolgenerate"
	@echo "make target-supervisor  J5: kill -9 the authority, fail closed, supervised restart, crash-loop give-up"
	@echo "make target-kxgw     host <-> target gateways over TCP: roles, escalation push, hostile input"
	@echo "make target-bridge   host bridge (REST + WebSocket) end to end against the QNX gateways"
	@echo "make target-agent    scripted agent scenes 1-3 against QNX, dossier verified"
	@echo "make target-selftest kx-selftest on QNX (dev image) + offline verify of its dossier"
	@echo "make target-selftest-secure  the same on the --secpol=secure release image"
	@echo "make target-bench    kx-bench: latency + HMI under an agent flood (headline numbers: RPi4 only)"
	@echo "make target-policy   signed policy bundles: refuse / activate / persist / replay on QNX"
	@echo "make codelab         run the secpol codelab end to end on QNX (codelab/README.md)"
	@echo "make qemu-stop       stop the VM"

node_modules: package.json package-lock.json
	npm ci --no-audit --no-fund
	@touch node_modules

codegen: node_modules
	npm run -s codegen

codegen-check: node_modules
	npm run -s codegen:check

host:
	cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Debug
	cmake --build build/host

# data-race check of the lock-free telemetry seqlock
tsan:
	cc -std=c11 -O1 -g -fsanitize=thread -Itarget/include target/libkxsim/tests/test_seqlock.c \
	  target/libkxcore/src/catalog_gen.c -o build/test_seqlock_tsan -lpthread
	build/test_seqlock_tsan

# libFuzzer on the gateway's JSON-lines parser (needs clang with libFuzzer, e.g. Linux; FUZZ_SECONDS=60)
FUZZ_SECONDS ?= 60
fuzz-wire:
	mkdir -p build/fuzz-corpus
	clang -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined -Itarget/include target/kxgw/tests/fuzz_wire.c \
	  target/kxgw/wire.c target/libkxcore/src/jcs.c target/libkxcore/src/sha256.c target/libkxcore/src/catalog_gen.c \
	  -o build/fuzz_wire
	build/fuzz_wire -max_total_time=$(FUZZ_SECONDS) -max_len=4200 build/fuzz-corpus

# libkxcore -> WebAssembly replay engine for kervix-verify (host/verify/kxcore.wasm)
wasm:
	wasm/build.sh

asan:
	cmake -S . -B build/asan -DCMAKE_BUILD_TYPE=Debug \
	  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
	cmake --build build/asan
	ctest --test-dir build/asan --output-on-failure

test: host codegen-check
	ctest --test-dir build/host --output-on-failure
	npm run -s test:host
	npm run -s typecheck
	npm run -s spike:s5
	npm run -s conformance

target: $(addprefix target-,$(ARCHES))

target-%:
	docker/qnx-build.sh cmake -S . -B build/qnx-$* -G Ninja \
	  -DCMAKE_TOOLCHAIN_FILE=cmake/qnx-$*.cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo
	docker/qnx-build.sh cmake --build build/qnx-$*

qnx-shell:
	docker/qnx-build.sh

qemu-image:
	scripts/qemu.sh image

qemu-start:
	scripts/qemu.sh start
	scripts/qemu.sh wait

qemu-stop:
	scripts/qemu.sh stop

qemu-ssh:
	scripts/qemu.sh ssh

# Run the portable-core unit tests on QNX itself (same binaries as the target build).
target-test: target-x86_64
	scripts/qemu.sh status | grep -q running || $(MAKE) qemu-start
	scripts/qemu.sh ssh 'mkdir -p /data/kervix/tests'
	scripts/qemu.sh scp $(addprefix build/qnx-x86_64/target/,$(KX_CORE_TESTS)) /data/kervix/tests/
	scripts/qemu.sh ssh 'cd /data/kervix/tests && uname -a && for t in $(notdir $(KX_CORE_TESTS)); do echo "== $$t"; ./$$t || exit 1; done'

# vsimd + kxctl acceptance on QNX (16 checks)
target-vsim:
	tests/target/vsim.sh

# M1 authority MVP acceptance on QNX: vsimd + kervixd + sdv_actuatord + kxctl
target-m1:
	tests/target/m1.sh

# human oversight (ESCALATE -> driver approve/deny/timeout) acceptance on QNX
target-escalation:
	tests/target/escalation.sh

# signed ledger: keys, capsules, export, offline verify, tampering, crash recovery, K3
target-ledger:
	tests/target/ledger.sh

# kernel-enforced least privilege: typed boot, legitimate roles, kx-rogue red team
target-secpol:
	tests/target/secpol.sh open

# the four network gateways end to end (host TCP -> kxgw -> kervixd / actuator / vsimd)
target-kxgw:
	tests/target/kxgw.sh

# host/bridge (REST + WebSocket) against the QNX gateways
target-bridge: node_modules
	tests/target/bridge.sh

# scripted agent (demo scenes 1-3) through the bridge against QNX; dossier verified
target-agent: node_modules
	tests/target/agent.sh

# kx-selftest: every journey + attack ON the target, one PASS/FAIL table; dossier verified here
target-selftest:
	tests/target/selftest.sh open

target-selftest-secure:
	tests/target/selftest.sh secure

# kx-bench: PROPOSE/EXECUTE latency + driver HMI under an agent flood (QEMU numbers are emulated)
target-bench:
	tests/target/bench.sh -n 2000 -f 4 -s 5 --json

# signed policy bundles: author + approver, verified on the vehicle, activated, persisted, replayed
target-policy: node_modules
	tests/target/policy.sh

# the codelab (codelab/README.md), every step on QNX 8.0 in QEMU, checked
codelab:
	codelab/run.sh

# release image: --secpol=secure, kervix + monitor + harvested system policy
target-secpol-secure:
	tests/target/secpol.sh secure

secpol-harvest:
	scripts/secpol-harvest.sh

# J5: crash -> fail closed -> supervised restart -> recovery recorded in the ledger
target-supervisor:
	tests/target/supervisor.sh

clean:
	rm -rf build
