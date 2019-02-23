#include "gba.h"

#include "common/logger.h"

namespace gba {
	gba::gba(std::string& rom_name):
		clock(0),	
		mmu(::gba::mem::map),
		rom(rom_name)
	{
		STATUS("starting emulation");
	}

	gba::~gba() {
		STATUS("stopping emulation");
	}
} //namespace gba