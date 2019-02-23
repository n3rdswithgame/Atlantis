#ifndef ARM_H
#define ARM_H

//handles ARM + Thumb even though its named just arm

#include "cpu.h"
#include "ins.h"
#include "lifter.h"

namespace arm {
	struct emu_traits {
		using isa_t 	= arm::isa;
		using cpu_t		= arm::cpu::state;
		using ins_t		= arm::ins_t;
	};
} //namespace arm

#endif //ARM_H