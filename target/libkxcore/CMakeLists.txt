# libkxcore: the PORTABLE core (policy evaluation, intent/capsule JCS, grant
# table, ring). Rules: C11 only, no OS headers, no I/O, no clocks, no malloc.
# The same code runs on QNX, in host tests and in the offline replay verifier.
add_library(kxcore STATIC
  src/catalog_gen.c
  src/policy.c
  src/sha256.c
  src/jcs.c
  src/intent.c
  src/grant.c
)
target_include_directories(kxcore PUBLIC ${PROJECT_SOURCE_DIR}/target/include)
