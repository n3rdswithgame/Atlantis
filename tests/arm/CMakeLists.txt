#TODO make registering a test a macro

add_executable(arm_tests
	arm_test.cc

	lift_arm.cc
	lift_thumb.cc

	moc.h
)

target_link_libraries(arm_tests PRIVATE testing)

add_test(NAME arm COMMAND $<TARGET_FILE:arm_tests>)