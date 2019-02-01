#TODO make registering a test a macro

add_executable(mmu_tests
	mmu_test.cc
)

target_link_libraries(mmu_tests PRIVATE testing)

add_test(NAME mmu COMMAND $<TARGET_FILE:mmu_tests>)