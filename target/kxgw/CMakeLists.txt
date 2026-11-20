add_executable(kxgw kxgw.c wire.c)
target_link_libraries(kxgw PRIVATE kxcore secpol socket)
