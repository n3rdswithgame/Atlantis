#ifndef ARM_DEC_H
#define ARM_DEC_H

#include "dispatch.h"

#include "dataProcessing.h"
#include "branching.h"
#include "supervisor.h"
#include "unconditional.h"

#include "core/arm/arm.h"
#include "core/arm/ins/ins.h"

#include "common/types.h"


namespace arm::dec::a {
	using bit::mask::negation;

	//TODO: sitdown and spend a day and half doing this
	status Conditional(addr_t addr, u32 ins, out<arm::ins_t> i);

	ins_t decode(addr_t addr, u32 ins) {
		arm::ins_t i;

		i.raw = ins;

		status s = dispatch<
						decoder<		   arm_mask::Unconditional, Unconditional>,
						decoder< negation<arm_mask::Unconditional>, Conditional>
				   >(addr, ins, i);

		if(s == status::future) {
			i.op = arm::operation::future;
		}

		return i;
	}
	

	inline status Conditional(addr_t addr, u32 ins, out<arm::ins_t> i) {
		i.cond = static_cast<arm::cond>(bit::mask::range<31,28>::strip(ins));

		return dispatch<
			decoder<arm_mask::DataProcessingLike, DataProcessingLike>,
			decoder<arm_mask::BranchImm, BranchImm>,
			decoder<arm_mask::SVC, Svc>
		>(addr, ins, i);
	}

}//namespace arm::dec::a
#endif //ARM_DEC_H