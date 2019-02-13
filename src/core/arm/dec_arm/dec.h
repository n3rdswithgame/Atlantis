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



namespace arm::dec::arm {
	//TODO: sitdown and spend a day and half doing this
	status conditional(addr_t addr, u32 ins, out<::arm::ins_t> i);

	ins_t decode(addr_t addr, u32 ins) {
		::arm::ins_t i;

		i.raw = ins;

		status s = dispatch<
						decoder<arm_mask::Unconditional, Unconditional>
				   >(addr, ins, i);

		if (s != status::success && s != status::future) {
			s = conditional(addr, ins, i);
		}

		if(s == status::future) {
			i.op = ::arm::operation::future;
		}

		return i;
	}
	

	inline status conditional(addr_t addr, u32 ins, out<::arm::ins_t> i) {
		return dispatch<
			decoder<arm_mask::DataProcessing, dataProcessing>,
			decoder<arm_mask::BranchImm, branchImm>,
			decoder<arm_mask::SVC, Svc>
		>(addr, ins, i);
	}

}//namespace arm::dec
#endif //ARM_DEC_H