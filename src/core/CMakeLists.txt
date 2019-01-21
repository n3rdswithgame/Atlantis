add_library(core STATIC
	cpu.h
	cpu.cc
)

target_link_libraries(core PUBLIC common)
target_link_libraries(core PRIVATE project_warnings)
