add_library(core STATIC

	arm/arm.h
	arm/cpu.h
	arm/cpu.cc
	arm/ins.h
	arm/lifter.h
	arm/lifter.cc

	ast/ast.h
	ast/basic_block.h
	ast/dispatcher.h
	ast/executor.h
	ast/lifter.h
	ast/types.h

	gba/gba.h
	gba/gba.cc
	gba/mbc.h
	gba/memmap.h
	gba/rom.h
	gba/rom.cc
	gba/types.h

	mem.h
	mem.cc

	mmu.h
	mmu.cc

	targets.h
)

target_link_libraries(core PUBLIC common)
target_link_libraries(core PUBLIC capstone-static)
target_link_libraries(core PRIVATE project_warnings)

target_include_directories(core PUBLIC core)