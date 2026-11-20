# qnx-build: x86_64 Ubuntu container that runs the QNX SDP 8.0 *Linux* host
# tools on macOS (including Apple Silicon, through Docker's amd64 emulation).
# The SDP itself is NOT baked into the image: it is licensed per developer and
# bind-mounted from ~/qnx800 at runtime (see docker/qnx-build.sh).
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates cmake ninja-build make python3 file rsync \
      openssh-client xz-utils zip unzip cpio genisoimage mtools dosfstools \
    && rm -rf /var/lib/apt/lists/*

# The SDP's environment script is sourced for every command run through
# docker/qnx-build.sh, so qcc, mkqnximage and friends are on PATH.
WORKDIR /work
CMD ["bash"]
