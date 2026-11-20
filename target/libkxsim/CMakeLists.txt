# libkxsim: portable vehicle model behind vsimd (C11, no OS deps, no malloc).
add_library(kxsim STATIC src/sim.c)
target_include_directories(kxsim PUBLIC ${PROJECT_SOURCE_DIR}/target/include)
target_link_libraries(kxsim PUBLIC kxcore)
