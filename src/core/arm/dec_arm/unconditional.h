#ifndef DEC_ARM_UNCONDITIONAL_H
#define DEC_ARM_UNCONDITIONAL_H

#include "core/arm/arm.h"

#include "common/types.h"

namespace arm::dec::arm {
	status Unconditional(addr_t, u32, out<::arm::ins_t> i) {
		i.cond = ::arm::cond::al;
		return status::success;
	}
} //namespace arm::dec::arm

#endif //DEC_ARM_UNCONDITIONAL_H