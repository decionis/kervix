add_executable(test_catalog test_catalog.c)
target_link_libraries(test_catalog PRIVATE kxcore)
add_test(NAME catalog COMMAND test_catalog)

add_executable(test_policy test_policy.c default_policy.c)
target_link_libraries(test_policy PRIVATE kxcore)
# positional partial initializers keep the policy table readable
target_compile_options(test_policy PRIVATE -Wno-missing-field-initializers)
add_test(NAME policy COMMAND test_policy)
