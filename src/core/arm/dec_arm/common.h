#ifndef DEC_ARM_COMMON_H
#define DEC_ARM_COMMON_H

#include "common/types.h"
#include "common/bit/mask.h"

#include "core/arm/arm.h"

namespace arm::dec::a {

	template<size_t high>
	constexpr u32 extractReg(u32 val) {
		return static_cast<u32>(
					bit::mask::range<high, high-3>::extract(val)
				);
	}

	constexpr u32 extractRd(u32 val) {
		return extractReg<15>(val);
	}

	constexpr u32 extractRn(u32 val) {
		return extractReg<19>(val);
	}

	constexpr u32 extractRs(u32 val) {
		return extractReg<11>(val);
	}

	constexpr u32 extractRm(u32 val) {
		return extractReg<3>(val);
	}

	constexpr auto make_op_rr_is(cpu::reg rd, cpu::reg rn, cpu::reg rm, arm_parts::shift type, u8 shift) -> operand::rr_is{
		operand::rr_is rr_is{};
		
		rr_is.rd = rd;
		rr_is.rn = rn;
		rr_is.rm = rm;
		rr_is.type = type;
		rr_is.shift = shift;
		
		return rr_is;
	}

	constexpr auto make_op_rr_rs(cpu::reg rd, cpu::reg rn, cpu::reg rm, arm_parts::shift type, cpu::reg rs) -> operand::rr_rs{
		operand::rr_rs rr_rs{};

		rr_rs.rd = rd;
		rr_rs.rn = rn;
		rr_rs.rm = rm;
		rr_rs.type = type;
		rr_rs.rs = rs;

		return rr_rs;
	}

	constexpr auto make_op_rr_ui(cpu::reg rd, cpu::reg rn, u32 imm) -> operand::rr_ui{
		operand::rr_ui rr_ui{};

		rr_ui.rd = rd;
		rr_ui.rn = rn;
		rr_ui.imm = imm;

		return rr_ui;
	}

	constexpr auto make_op_rr_si(cpu::reg rd, cpu::reg rn, s32 imm) -> operand::rr_si{
		operand::rr_si rr_si{};

		rr_si.rd = rd;
		rr_si.rn = rn;
		rr_si.imm = imm;

		return rr_si;
	}

	constexpr auto make_op_ui(u32 imm) -> operand::ui{
		operand::ui ui{};

		ui.imm = imm;

		return ui;
	}

	constexpr auto make_op_si(s32 imm) -> operand::si{
		operand::si si{};

		si.imm = imm;

		return si;
	}

	constexpr auto make_reglist	(u32 rl) -> operand::reglist{
		operand::reglist reglist{};

		reglist.rl = rl;

		return reglist;
	}


} //namespace arm::dec::a

#endif //DEC_ARM_COMMON_H