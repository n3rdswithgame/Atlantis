#ifndef GBA_H
#define GBA_H

#include "mbc.h"
#include "memmap.h"
#include "rom.h"

#include "core/arm/"
#include "core/arm/cpu.h"
#include "core/mmu.h"




namespace gba {
	class gba {
		arm::cpu::cpu cpu;
		//mmu::mmu<arm::mem::map> mmu;

	};
} //namespace gba

#endif