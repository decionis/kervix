# Shared QNX SDP 8.0 toolchain settings. Included by qnx-<arch>.cmake.
# Requires the SDP environment (source qnxsdp-env.sh), which sets
# QNX_HOST and QNX_TARGET. In this repo that happens inside the qnx-build
# container (see docker/), because SDP 8.0 has no macOS/ARM host tools.
# STATUS: unverified until spike S6. Update docs/decisions.md with the result.

if(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})
  message(FATAL_ERROR "QNX_HOST/QNX_TARGET not set: source qnxsdp-env.sh (use `make target`, which runs in the qnx-build container)")
endif()

set(CMAKE_SYSTEM_NAME QNX)
set(CMAKE_SYSTEM_VERSION 8.0.0)

set(QNX_HOST   "$ENV{QNX_HOST}")
set(QNX_TARGET "$ENV{QNX_TARGET}")

set(CMAKE_C_COMPILER   "${QNX_HOST}/usr/bin/qcc")
set(CMAKE_CXX_COMPILER "${QNX_HOST}/usr/bin/q++")
set(CMAKE_C_COMPILER_TARGET   "${KX_QNX_VARIANT}")
set(CMAKE_CXX_COMPILER_TARGET "${KX_QNX_VARIANT}_cxx")

set(CMAKE_SYSROOT "${QNX_TARGET}")
set(CMAKE_FIND_ROOT_PATH "${QNX_TARGET}" "${QNX_TARGET}/${KX_QNX_CPUDIR}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Expose QNX extensions (resmgr, secpol, ...) even with -std=c11.
add_compile_definitions(_QNX_SOURCE)
