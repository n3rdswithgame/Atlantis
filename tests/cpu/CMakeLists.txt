#TODO make registering a test a macro

add_executable(cpu_tests
	cpu_test.cc
	registers.cc
)

target_link_libraries(cpu_tests PRIVATE testing)

add_test(NAME cpu COMMAND $<TARGET_FILE:cpu_tests>)