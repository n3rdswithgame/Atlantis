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

	ins_t decodeArm(addr_t addr, u32 ins) {
		::arm::ins_t i;

		//TODO:profile for optimal reserve-then-shrinking size
		//and then profile whether reserve-then-shrinking or
		//ad-hoc reserving is better

		//there should be no more than ~13 operands to any instruction
		//so bulk reserve now and then trim before return
		i.operands.reserve(10);

		status s = dispatch<
						decoder<arm_mask::Unconditional, Unconditional>
				   >(addr, ins, i);

		if (s != status::success && s != status::future) {
			s = conditional(addr, ins, i);
		}

		if(s == status::future) {
			i.op = ::arm::operation::future;
		}

		//trim the vector down
		i.operands.shrink_to_fit();

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