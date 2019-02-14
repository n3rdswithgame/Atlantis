#ifndef DEC_ARM_UNCONDITIONAL_H
#define DEC_ARM_UNCONDITIONAL_H

#include "core/arm/arm.h"

#include "common/types.h"

namespace arm::dec::a {
	inline status Unconditional(addr_t addr, u32 ins, out<arm::ins_t> i) {
		i.cond = arm::cond::al;
		//currently no unconditional arm operand is
		//defined (current goal is up to ARMv4)
		//TODO: change when I go past ARMv4
		i.op = arm::operation::undef;
		return Future(addr, ins, i);
	}
} //namespace arm::dec::a

#endif //DEC_ARM_UNCONDITIONAL_H