add_executable(test_catalog test_catalog.c)
target_link_libraries(test_catalog PRIVATE kxcore)
add_test(NAME catalog COMMAND test_catalog)

add_executable(test_policy test_policy.c)
target_link_libraries(test_policy PRIVATE kxcore)
# positional partial initializers keep the policy table readable
target_compile_options(test_policy PRIVATE -Wno-missing-field-initializers)
add_test(NAME policy COMMAND test_policy)

add_executable(test_sha256 test_sha256.c)
target_link_libraries(test_sha256 PRIVATE kxcore)
add_test(NAME sha256 COMMAND test_sha256)

add_executable(test_intent test_intent.c)
target_link_libraries(test_intent PRIVATE kxcore)
add_test(NAME intent COMMAND test_intent)

add_executable(test_grant test_grant.c)
target_link_libraries(test_grant PRIVATE kxcore)
target_compile_options(test_grant PRIVATE -Wno-missing-field-initializers)
add_test(NAME grant COMMAND test_grant)

add_executable(test_ratelimit test_ratelimit.c)
target_link_libraries(test_ratelimit PRIVATE kxcore)
add_test(NAME ratelimit COMMAND test_ratelimit)

add_executable(test_capsule test_capsule.c)
target_link_libraries(test_capsule PRIVATE kxcore)
add_test(NAME capsule COMMAND test_capsule)

add_executable(test_ledger test_ledger.c)
target_link_libraries(test_ledger PRIVATE kxcore)
add_test(NAME ledger COMMAND test_ledger)

add_executable(test_policy_load test_policy_load.c)
target_link_libraries(test_policy_load PRIVATE kxcore)
target_compile_definitions(test_policy_load PRIVATE KX_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures")
add_test(NAME policy_load COMMAND test_policy_load)

add_executable(test_bundle test_bundle.c)
target_link_libraries(test_bundle PRIVATE kxcore)
add_test(NAME bundle COMMAND test_bundle)
