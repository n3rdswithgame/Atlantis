#ifndef DEC_ARM_DATAPROCESSING_H
#define DEC_ARM_DATAPROCESSING_H

#include "common.h"
#include "status.h"

#include "common/types.h"
#include "common/unreachable.h"

#include "core/arm/arm.h"

namespace arm::dec::a {
	status dpImmShift(addr_t, u32, out<arm::ins_t>);
	status dpRegShift(addr_t, u32, out<arm::ins_t>);
	status dpImm(addr_t, u32, out<arm::ins_t>);

	template<arm_parts::dp op>
	status dp_dec_func(addr_t, u32, out<arm::ins_t>);
	template<arm_parts::dp op>
	using dp_decoder = decoder<arm_parts::dp_mask<op>, dp_dec_func<op>>;

	constexpr arm::operation dp_to_op(arm_parts::dp dpOp);

	inline status dataProcessing(addr_t addr, u32 ins, out<arm::ins_t> i) {
		return dispatch<
			decoder<arm_mask::DPExtension, Discard>,
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
	inline status dp_dec_func(addr_t addr, u32 ins, out<arm::ins_t> i) {
		i.op = dp_to_op(dpOp);
		return dispatch<
			decoder<arm_mask::DPImmShift, dpImmShift>,
			decoder<arm_mask::DPRegShift, dpRegShift>,
			decoder<arm_mask::DPImm, 	  dpImm>
		>(addr, ins, i);
	}

	inline constexpr arm::operation dp_to_op(arm_parts::dp dpOp) {
		#define dp_to_op_mapping(d, o)		\
		case arm_parts::dp::d :				\
			return arm::operation::o
		
		switch(dpOp) {
			dp_to_op_mapping(And, And);
			dp_to_op_mapping(Eor, Eor);
			dp_to_op_mapping(Sub, Sub);
			dp_to_op_mapping(Rsb, Rsb);
			dp_to_op_mapping(Add, Add);
			dp_to_op_mapping(Adc, Adc);
			dp_to_op_mapping(Sbc, Sbc);
			dp_to_op_mapping(Rsc, Rsc);
			dp_to_op_mapping(Tst, Tst);
			dp_to_op_mapping(Teq, Teq);
			dp_to_op_mapping(Cmp, Cmp);
			dp_to_op_mapping(Cmn, Cmn);
			dp_to_op_mapping(Orr, Orr);
			dp_to_op_mapping(Mov, Mov);
			dp_to_op_mapping(Bic, Bic);
			dp_to_op_mapping(Mvn, Mvn);
		}
		return UNREACHABLE(arm::operation);
		#undef dp_to_op_mapping
	}

	inline status dpImmShift(addr_t, u32 ins, out<arm::ins_t> i) {
		cpu::reg rn = extractRn(ins);
		cpu::reg rd = extractRd(ins);
		cpu::reg rm = extractRm(ins);
		arm_parts::shift type = static_cast<arm_parts::shift>(bit::mask::range<6,5>::strip(ins));
		u8 shift = static_cast<u8>(bit::mask::range<11,7>::extract(ins));

		i.operands = make_op_rr_is(rd, rn, rm, type, shift);

		return status::success;

	}

	inline status dpRegShift(addr_t, u32 ins, out<arm::ins_t> i) {

		cpu::reg rn = extractRn(ins);
		cpu::reg rd = extractRd(ins);
		cpu::reg rm = extractRm(ins);
		arm_parts::shift type = static_cast<arm_parts::shift>(bit::mask::range<6,5>::strip(ins));
		cpu::reg rs = extractRs(ins);

		i.operands = make_op_rr_rs(rd, rn, rm, type, rs);

		return status::success;

	}

	inline status dpImm(addr_t, u32 ins, out<arm::ins_t> i) {
		cpu::reg rn = extractRn(ins);
		cpu::reg rd = extractRd(ins);
		u8 rot = static_cast<u8>(bit::mask::range<11,8>::strip(ins));
		u8 imm = static_cast<u8>(bit::mask::range<7,0>::strip(ins));

		i.operands = make_op_rr_ui(rd, rn, rotateImm(rot, imm));

		return status::success;

	}
} //namespace arm::dec::a

#endif //DEC_ARM_DATAPROCESSING_H