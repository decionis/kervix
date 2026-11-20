# Native-arch (arm64 on Apple Silicon) image with clang + lld for the libkxcore
# WebAssembly build. No QNX SDP needed.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends clang lld make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
