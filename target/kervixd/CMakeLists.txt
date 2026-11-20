add_executable(kervixd kervixd.c kxledger.c)
target_link_libraries(kervixd PRIVATE kxcore secpol qcrypto)
