#ifndef GBA_H
#define GBA_H

#include "mbc.h"
#include "memmap.h"
#include "rom.h"

#include <string>

#include "mbc.h"
#include "memmap.h"
#include "rom.h"

#include "core/arm/arm.h"
#include "core/arm/cpu.h"
#include "core/mmu.h"




namespace gba {
	class gba {
		arm::cpu::state cpu;
		mmu::mmu<::gba::mem::region> mmu;
		rom::rom rom;

	public:
		gba(std::string&);
		~gba();
	};
} //namespace gba

#endif