add_executable(test_wire test_wire.c ../wire.c)
target_include_directories(test_wire PRIVATE ${PROJECT_SOURCE_DIR}/target/libkxcore/tests)
target_link_libraries(test_wire PRIVATE kxcore)
add_test(NAME kxgw_wire COMMAND test_wire)
