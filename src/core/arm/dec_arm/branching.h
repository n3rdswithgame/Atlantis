#ifndef DEC_ARM_BRANCHING_H
#define DEC_ARM_BRANCHING_H

#include "core/arm/arm.h"

#include "common/types.h"

namespace arm::dec::arm {
	status branchImm(addr_t, u32, out<::arm::ins_t>) {
		DEBUG("Branching called");
		return status::nomatch;
	}
} //namespace arm::dec::arm

#endif //DEC_ARM_BRANCHING_H