cmake_minimum_required(VERSION 3.20)
project(kervix VERSION 0.1.0 LANGUAGES C)

# Two build flavours:
#   host  (macOS/Linux, native compiler): portable libkxcore + unit tests
#   QNX   (CMAKE_TOOLCHAIN_FILE=cmake/qnx-<arch>.cmake, inside the qnx-build
#          container): libkxcore + the on-target daemons and tools
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SYSTEM_NAME STREQUAL "QNX")
  set(KX_QNX ON)
else()
  set(KX_QNX OFF)
endif()

option(KX_BUILD_TESTS "Build host unit tests" ${KX_QNX})
if(NOT KX_QNX)
  set(KX_BUILD_TESTS ON CACHE BOOL "" FORCE)
endif()

# Strict warnings everywhere. libkxcore must stay warning-free on clang and gcc.
add_compile_options(-Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wpointer-arith -Wformat=2)

add_subdirectory(target/libkxcore)

if(KX_QNX)
  add_subdirectory(spikes/s1-secpol)
  add_subdirectory(spikes/s3-qcrypto)
  # On-target components are added as they are implemented (M1+):
  # add_subdirectory(target/vsimd)
  # add_subdirectory(target/kervixd)
  # add_subdirectory(target/sdv_actuatord)
  # add_subdirectory(target/kxctl)
endif()

if(KX_BUILD_TESTS)
  enable_testing()
  add_subdirectory(target/libkxcore/tests)
endif()
