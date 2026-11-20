# QNX SDP 8.0, aarch64le target (Raspberry Pi 4; optional QEMU virt).
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(KX_QNX_VARIANT gcc_ntoaarch64le)
set(KX_QNX_CPUDIR aarch64le)
include(${CMAKE_CURRENT_LIST_DIR}/qnx-common.cmake)
