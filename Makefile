# Kervix top-level shortcuts. Host targets run natively. QNX targets run in
# the qnx-build container (docker/qnx-build.sh), which works on macOS and Linux.
.PHONY: help host asan test codegen codegen-check spikes target qnx-shell qemu-image qemu-start qemu-stop qemu-ssh target-test clean

ARCHES ?= x86_64 aarch64le
KX_CORE_TESTS = test_catalog test_policy test_sha256 test_intent test_grant

help:
	@echo "make host            build libkxcore + host tests (native)"
	@echo "make test            run host unit tests + codegen check + spikes"
	@echo "make asan            host unit tests under AddressSanitizer + UBSan"
	@echo "make codegen         regenerate C/TS/tool schemas from catalog/catalog.yaml"
	@echo "make target          build QNX 8.0 binaries for: $(ARCHES) (needs SDP, see docs/setup-macos.md)"
	@echo "make qnx-shell       interactive shell with the QNX SDP environment"
	@echo "make qemu-image      build the QNX 8.0 x86_64 QEMU image (mkqnximage, in the container)"
	@echo "make qemu-start      boot it headless on this machine (ssh on localhost:2222)"
	@echo "make target-test     cross-build, copy and run libkxcore tests ON QNX (QEMU)"
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

asan:
	cmake -S . -B build/asan -DCMAKE_BUILD_TYPE=Debug \
	  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
	cmake --build build/asan
	ctest --test-dir build/asan --output-on-failure

test: host codegen-check
	ctest --test-dir build/host --output-on-failure
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
	scripts/qemu.sh scp $(addprefix build/qnx-x86_64/target/libkxcore/tests/,$(KX_CORE_TESTS)) /data/kervix/tests/
	scripts/qemu.sh ssh 'cd /data/kervix/tests && uname -a && for t in $(KX_CORE_TESTS); do ./$$t || exit 1; done'

clean:
	rm -rf build
