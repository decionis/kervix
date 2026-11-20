add_executable(test_catalog test_catalog.c)
target_link_libraries(test_catalog PRIVATE kxcore)
add_test(NAME catalog COMMAND test_catalog)
