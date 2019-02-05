add_library(core STATIC

	ast/ast.h
	ast/basic_block.h
	ast/dispatcher.h
	ast/lifter.h

	arm/arm.h
	arm/cpu.h
	arm/cpu.cc
	arm/lifter.h
	arm/lifter.cc

	gba/gba.h
	gba/gba.cc
	gba/mbc.h
	gba/memmap.h
	gba/rom.h
	gba/rom.cc

	mmu.h
	mmu.cc

	mem.h
	mem.cc
)

target_link_libraries(core PUBLIC common)
target_link_libraries(core PUBLIC capstone-static)
target_link_libraries(core PRIVATE project_warnings)

target_include_directories(core PUBLIC core)