add_library(core STATIC
	cpu.h
	cpu.cc

	mmu.h
	mmu.cc

	mem.h
	mem.cc

	ast/ast.h
)

target_link_libraries(core PUBLIC common)
target_link_libraries(core PRIVATE project_warnings)
