#include "gba.h"

#include "common/logger.h"

namespace gba {
	gba::gba(std::string& rom_name):
		mmu(::gba::mem::map),
		rom(rom_name)
	{
		STATUS("starting emulation");
	}

	gba::~gba() {
		STATUS("stopping emulation");
	}
} //namespace gba