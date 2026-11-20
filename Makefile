# Kervix top-level shortcuts. Host targets run natively. QNX targets run in
# the qnx-build container (docker/qnx-build.sh), which works on macOS and Linux.
.PHONY: help host asan test codegen codegen-check spikes target target-x86_64 target-aarch64le qnx-shell clean

ARCHES ?= x86_64 aarch64le

help:
	@echo "make host            build libkxcore + host tests (native)"
	@echo "make test            run host unit tests + codegen check + spikes"
	@echo "make asan            host unit tests under AddressSanitizer + UBSan"
	@echo "make codegen         regenerate C/TS/tool schemas from catalog/catalog.yaml"
	@echo "make target          build QNX 8.0 binaries for: $(ARCHES) (needs SDP, see docs/setup-macos.md)"
	@echo "make qnx-shell       interactive shell with the QNX SDP environment"

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

target: $(addprefix target-,$(ARCHES))

target-%:
	docker/qnx-build.sh cmake -S . -B build/qnx-$* -G Ninja \
	  -DCMAKE_TOOLCHAIN_FILE=cmake/qnx-$*.cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo
	docker/qnx-build.sh cmake --build build/qnx-$*

qnx-shell:
	docker/qnx-build.sh

clean:
	rm -rf build
