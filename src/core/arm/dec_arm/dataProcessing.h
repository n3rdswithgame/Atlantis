#ifndef DEC_ARM_DATAPROCESSING_H
#define DEC_ARM_DATAPROCESSING_H

#include "status.h"

#include "common/types.h"

#include "core/arm/arm.h"

namespace arm::dec::arm {
	status dpImmShift(addr_t, u32, out<::arm::ins_t>);
	status dpRegShift(addr_t, u32, out<::arm::ins_t>);
	status dpImm(addr_t, u32, out<::arm::ins_t>);

	template<arm_parts::dp op>
	status dp_dec_func(addr_t, u32, out<::arm::ins_t>);
	template<arm_parts::dp op>
	using dp_decoder = decoder<arm_parts::dp_mask<op>, dp_dec_func<op>>;

	constexpr ::arm::operation dp_to_op(arm_parts::dp dpOp);

	inline status dataProcessing(addr_t addr, u32 ins, out<::arm::ins_t> i) {
		return dispatch<
			dp_decoder<arm_parts::dp::And>,
			dp_decoder<arm_parts::dp::Eor>,
			dp_decoder<arm_parts::dp::Sub>,
			dp_decoder<arm_parts::dp::Rsb>,
			dp_decoder<arm_parts::dp::Add>,
			dp_decoder<arm_parts::dp::Adc>,
			dp_decoder<arm_parts::dp::Sbc>,
			dp_decoder<arm_parts::dp::Rsc>,
			dp_decoder<arm_parts::dp::Tst>,
			dp_decoder<arm_parts::dp::Teq>,
			dp_decoder<arm_parts::dp::Cmp>,
			dp_decoder<arm_parts::dp::Cmn>,
			dp_decoder<arm_parts::dp::Orr>,
			dp_decoder<arm_parts::dp::Mov>,
			dp_decoder<arm_parts::dp::Bic>,
			dp_decoder<arm_parts::dp::Mvn>
		>(addr, ins, i);
	}

	template<arm_parts::dp dpOp>
	inline status dp_dec_func(addr_t addr, u32 ins, out<::arm::ins_t> i) {
		i.op = dp_to_op(dpOp);
		return dispatch<
			decoder<arm_mask::DPImmShift, dpImmShift>,
			decoder<arm_mask::DPRegShift, dpRegShift>,
			decoder<arm_mask::DPImm, 	  dpImm>
		>(addr, ins, i);
	}

	inline constexpr ::arm::operation dp_to_op(arm_parts::dp dpOp) {
		#define mapping(d, o)				\
		case arm_parts::dp::d :				\
			return ::arm::operation::o
		
		switch(dpOp) {
			mapping(And, And);
			mapping(Eor, Eor);
			mapping(Sub, Sub);
			mapping(Rsb, Rsb);
			mapping(Add, Add);
			mapping(Adc, Adc);
			mapping(Sbc, Sbc);
			mapping(Rsc, Rsc);
			mapping(Tst, Tst);
			mapping(Teq, Teq);
			mapping(Cmp, Cmp);
			mapping(Cmn, Cmn);
			mapping(Orr, Orr);
			mapping(Mov, Mov);
			mapping(Bic, Bic);
			mapping(Mvn, Mvn);
		}

		#undef mapping
	}

	inline status dpImmShift(addr_t, u32, out<::arm::ins_t>) {
		return status::nomatch;

	}
	inline status dpRegShift(addr_t, u32, out<::arm::ins_t>) {
		return status::nomatch;

	}
	inline status dpImm(addr_t, u32, out<::arm::ins_t>) {
		return status::nomatch;

	}
} //namespace arm::dec::arm

#endif //DEC_ARM_DATAPROCESSING_H