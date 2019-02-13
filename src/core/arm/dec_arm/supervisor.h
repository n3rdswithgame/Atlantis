#ifndef DEC_ARM_SVC
#define DEC_ARM_SVC

#include "core/arm/arm.h"

#include "common/types.h"
#include "common/bit/mask.h"

namespace arm::dec::arm {
	inline status Svc(addr_t, u32 ins, out<::arm::ins_t> i) {

		i.op = ::arm::operation::Svc;

		u32 svcNum = static_cast<u32>(bit::mask::lower<24>::apply(ins));

		i.operands.push_back({operand_type::u_imm, svcNum});
		
		return status::success;
	}
} //namespace arm::dec::arm

#endif