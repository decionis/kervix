# Spike S1/S2 (QNX only): secpol per-path channel typing + client type ids.
add_executable(s1_server s1_server.c)
target_link_libraries(s1_server PRIVATE secpol)
add_executable(s1_client s1_client.c)
target_link_libraries(s1_client PRIVATE secpol)
