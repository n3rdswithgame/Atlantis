#ifndef GBA_H
#define GBA_H

#include "mbc.h"
#include "memmap.h"
#include "rom.h"
#include "types.h"

#include <string>

#include "mbc.h"
#include "memmap.h"
#include "rom.h"

#include "core/arm/arm.h"
#include "core/arm/cpu.h"
#include "core/mmu.h"




namespace gba {
	class gba {
		//each chip that has its own timer, but this is the common clock that counts
		//how much has been emulated so far
		emu_traits::tick_t clock;

		arm::cpu::state cpu;
		mmu::mmu<::gba::mem::region> mmu;
		rom::rom rom;

	public:
		gba(std::string&);
		~gba();
	};
} //namespace gba

#endif