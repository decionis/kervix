add_executable(test_sim test_sim.c)
target_link_libraries(test_sim PRIVATE kxsim)
add_test(NAME sim COMMAND test_sim)

find_package(Threads REQUIRED)
add_executable(test_seqlock test_seqlock.c)
target_link_libraries(test_seqlock PRIVATE kxcore Threads::Threads)
add_test(NAME seqlock COMMAND test_seqlock)
