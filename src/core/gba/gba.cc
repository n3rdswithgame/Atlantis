#include "gba.h"

#include "common/logger.h"

namespace gba {
	gba::gba(std::string& rom_name):
		mmu(::gba::mem::map),
		rom(rom_name)
	{
		DEBUG("starting emulation");
	}

	gba::~gba() {
		DEBUG("stopping emulation");
	}
} //namespace gba