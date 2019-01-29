#TODO make registering a test a macro

add_executable(register	registers.cc)

target_link_libraries(register PRIVATE testing)

add_test(NAME register_test COMMAND $<TARGET_FILE:register>)