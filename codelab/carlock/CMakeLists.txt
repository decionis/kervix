# Codelab (QNX only): the car-lock resource manager and its client.
add_executable(carlockd carlockd.c)
target_link_libraries(carlockd PRIVATE secpol)
add_executable(carlock carlock.c)
target_link_libraries(carlock PRIVATE secpol)
