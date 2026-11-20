add_executable(kervixd kervixd.c)
target_link_libraries(kervixd PRIVATE kxcore secpol qcrypto)
