#include "lifter.h"

#include "arm.h"
#include "cpu.h"

#include "common/logger.h"
#include "common/small_vec.h"

#include <iostream>
#include <string>
#include <vector>

#include <capstone/capstone.h>


namespace arm {

	//internal to this file only
	using operandList = std::vector<operand::box_val>;


	std::string csCCtoStr(arm_cc cc) {
		#define toStr(x) case ARM_CC_ ## x: return #x
		switch(cc) {
			toStr(EQ);
			toStr(NE);
			toStr(HS);
			toStr(LO);
			toStr(MI);
			toStr(PL);
			toStr(VS);
			toStr(VC);
			toStr(HI);
			toStr(LS);
			toStr(GE);
			toStr(LT);
			toStr(GT);
			toStr(LE);
			toStr(AL);
			default: break;
		}
		#undef toStr
		return "invalid";
	}
	std::string groupstr(u8 g) {
		#define toStr(x) case x: return #x
		switch(g) {
			toStr(ARM_GRP_INVALID);

			toStr(ARM_GRP_JUMP);
			toStr(ARM_GRP_CALL);
			toStr(ARM_GRP_INT);
			toStr(ARM_GRP_PRIVILEGE);
			toStr(ARM_GRP_BRANCH_RELATIVE);

			toStr(ARM_GRP_CRYPTO);
			toStr(ARM_GRP_DATABARRIER);
			toStr(ARM_GRP_DIVIDE);
			toStr(ARM_GRP_FPARMV8);
			toStr(ARM_GRP_MULTPRO);
			toStr(ARM_GRP_NEON);
			toStr(ARM_GRP_T2EXTRACTPACK);
			toStr(ARM_GRP_THUMB2DSP);
			toStr(ARM_GRP_TRUSTZONE);
			toStr(ARM_GRP_V4T);
			toStr(ARM_GRP_V5T);
			toStr(ARM_GRP_V5TE);
			toStr(ARM_GRP_V6);
			toStr(ARM_GRP_V6T2);
			toStr(ARM_GRP_V7);
			toStr(ARM_GRP_V8);
			toStr(ARM_GRP_VFP2);
			toStr(ARM_GRP_VFP3);
			toStr(ARM_GRP_VFP4);
			toStr(ARM_GRP_ARM);
			toStr(ARM_GRP_MCLASS);
			toStr(ARM_GRP_NOTMCLASS);
			toStr(ARM_GRP_THUMB);
			toStr(ARM_GRP_THUMB1ONLY);
			toStr(ARM_GRP_THUMB2);
			toStr(ARM_GRP_PREV8);
			toStr(ARM_GRP_FPVMLX);
			toStr(ARM_GRP_MULOPS);
			toStr(ARM_GRP_CRC);
			toStr(ARM_GRP_DPVFP);
			toStr(ARM_GRP_V6M);
			toStr(ARM_GRP_VIRTUALIZATION);

			toStr(ARM_GRP_ENDING);
		}
		#undef toStr
		return "unknown group";
	}
	std::string csRegToStr(int reg) {
		#define toStr(x) case ARM_REG_##x: return #x
		switch(reg){
			toStr(APSR);
			toStr(APSR_NZCV);
			toStr(CPSR);
			toStr(FPEXC);
			toStr(FPINST);
			toStr(FPSCR);
			toStr(FPSCR_NZCV);
			toStr(FPSID);
			toStr(ITSTATE);
			toStr(LR);
			toStr(PC);
			toStr(SP);
			toStr(SPSR);
			toStr(D0);
			toStr(D1);
			toStr(D2);
			toStr(D3);
			toStr(D4);
			toStr(D5);
			toStr(D6);
			toStr(D7);
			toStr(D8);
			toStr(D9);
			toStr(D10);
			toStr(D11);
			toStr(D12);
			toStr(D13);
			toStr(D14);
			toStr(D15);
			toStr(D16);
			toStr(D17);
			toStr(D18);
			toStr(D19);
			toStr(D20);
			toStr(D21);
			toStr(D22);
			toStr(D23);
			toStr(D24);
			toStr(D25);
			toStr(D26);
			toStr(D27);
			toStr(D28);
			toStr(D29);
			toStr(D30);
			toStr(D31);
			toStr(FPINST2);
			toStr(MVFR0);
			toStr(MVFR1);
			toStr(MVFR2);
			toStr(Q0);
			toStr(Q1);
			toStr(Q2);
			toStr(Q3);
			toStr(Q4);
			toStr(Q5);
			toStr(Q6);
			toStr(Q7);
			toStr(Q8);
			toStr(Q9);
			toStr(Q10);
			toStr(Q11);
			toStr(Q12);
			toStr(Q13);
			toStr(Q14);
			toStr(Q15);
			toStr(R0);
			toStr(R1);
			toStr(R2);
			toStr(R3);
			toStr(R4);
			toStr(R5);
			toStr(R6);
			toStr(R7);
			toStr(R8);
			toStr(R9);
			toStr(R10);
			toStr(R11);
			toStr(R12);
			toStr(S0);
			toStr(S1);
			toStr(S2);
			toStr(S3);
			toStr(S4);
			toStr(S5);
			toStr(S6);
			toStr(S7);
			toStr(S8);
			toStr(S9);
			toStr(S10);
			toStr(S11);
			toStr(S12);
			toStr(S13);
			toStr(S14);
			toStr(S15);
			toStr(S16);
			toStr(S17);
			toStr(S18);
			toStr(S19);
			toStr(S20);
			toStr(S21);
			toStr(S22);
			toStr(S23);
			toStr(S24);
			toStr(S25);
			toStr(S26);
			toStr(S27);
			toStr(S28);
			toStr(S29);
			toStr(S30);
			toStr(S31);
		}
		#undef toStr
		return "invalid";
	}
	std::string csShiftToStr(arm_shifter sh) {
		#define toStr(x) case ARM_SFT_ ## x: case ARM_SFT_ ## x ## _REG: return #x
		switch(sh) {
			toStr(ASR);
			toStr(LSL);
			toStr(LSR);
			toStr(ROR);
			toStr(RRX);
			case ARM_SFT_INVALID:
				break;
		}
		#undef toStr
		return "invalid shift";
	}
	bool isRegShift(arm_shifter sh) {
		return sh == ARM_SFT_ASR_REG
			|| sh == ARM_SFT_LSL_REG
			|| sh == ARM_SFT_LSR_REG
			|| sh == ARM_SFT_ROR_REG
			|| sh == ARM_SFT_RRX_REG;
	}

	void printInfo(cs_insn *ins) {
		DEBUG(
R"(
================================================================================
ARM Decoding:	{0:08x}	{1}  {2}
	{{
		cond	  : {3}
		op_count  : {4}
		update S  : {5}
		wb	  : {6}
		translate : {7}
		vec_size  : {8}
		raw	  : {9:02x}{10:02x}{11:02x}{12:02x}
	}})"
			, ins->address, ins->mnemonic, ins->op_str,
			csCCtoStr(ins->detail->arm.cc),
			ins->detail->arm.op_count,
			ins->detail->arm.update_flags,
			ins->detail->arm.writeback,
			ins->detail->arm.usermode,
			ins->detail->arm.vector_size,
			ins->bytes[3],
			ins->bytes[2],
			ins->bytes[1],
			ins->bytes[0]
			);
		for(int i = 0; i < ins->detail->groups_count; i++) {
			DEBUG("group[{}] = {}", i, groupstr(ins->detail->groups[i]));
		}
		for(int i = 0; i < ins->detail->arm.op_count; i++) {
			DEBUG("{2} op[{0}] = {1}", i, ins->detail->arm.operands[i], ins->detail->arm.operands[i].subtracted ? '-': ' ');
		}
	}

	void printInst(ins_t& i) {
		DEBUG(
R"(
--------------------------------------------
addr	: 0x{:08x}
raw	: 0x{:08x}
cond	: {}
op	: {}
)",
		i.addr,
		i.raw,
		i.cond,
		i.op
		);
		int j = 0;
		for(auto& op : i.operands) {
			DEBUG("op[{}] = {}", j++, op);
		}
	}

	std::pair<operand::op_type, s32> resolveCSRegister(int cs_reg) {
		using operand::op_type;
		switch(cs_reg) {
			case ARM_REG_INVALID:
			case ARM_REG_ENDING:
				return {op_type::empty, 0};
			case ARM_REG_APSR:
				return {op_type::psr, static_cast<s32>(cpu::sr::apsr)};
			case ARM_REG_APSR_NZCV:
				break;
			case ARM_REG_CPSR:
				return {op_type::psr, static_cast<s32>(cpu::sr::cpsr)};
			case ARM_REG_FPEXC:
				break;
			case ARM_REG_FPINST:
				break;
			case ARM_REG_FPSCR:
				break;
			case ARM_REG_FPSCR_NZCV:
				break;
			case ARM_REG_FPSID:
				break;
			case ARM_REG_ITSTATE:
				break;
			case ARM_REG_SPSR:
				return {op_type::psr, static_cast<s32>(cpu::sr::spsr)};
			case ARM_REG_D0:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d0)};
			case ARM_REG_D1:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d1)};
			case ARM_REG_D2:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d2)};
			case ARM_REG_D3:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d3)};
			case ARM_REG_D4:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d4)};
			case ARM_REG_D5:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d5)};
			case ARM_REG_D6:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d6)};
			case ARM_REG_D7:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d7)};
			case ARM_REG_D8:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d8)};
			case ARM_REG_D9:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d9)};
			case ARM_REG_D10:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d10)};
			case ARM_REG_D11:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d11)};
			case ARM_REG_D12:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d12)};
			case ARM_REG_D13:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d13)};
			case ARM_REG_D14:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d14)};
			case ARM_REG_D15:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d15)};
			case ARM_REG_D16:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d16)};
			case ARM_REG_D17:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d17)};
			case ARM_REG_D18:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d18)};
			case ARM_REG_D19:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d19)};
			case ARM_REG_D20:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d20)};
			case ARM_REG_D21:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d21)};
			case ARM_REG_D22:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d22)};
			case ARM_REG_D23:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d23)};
			case ARM_REG_D24:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d24)};
			case ARM_REG_D25:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d25)};
			case ARM_REG_D26:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d26)};
			case ARM_REG_D27:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d27)};
			case ARM_REG_D28:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d28)};
			case ARM_REG_D29:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d29)};
			case ARM_REG_D30:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d30)};
			case ARM_REG_D31:
				return {op_type::vpr_d, static_cast<s32>(cpu::vpr_d::d31)};
			case ARM_REG_FPINST2:
				break;
			case ARM_REG_MVFR0:
				break;
			case ARM_REG_MVFR1:
				break;
			case ARM_REG_MVFR2:
				break;
			case ARM_REG_Q0:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q0)};
			case ARM_REG_Q1:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q1)};
			case ARM_REG_Q2:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q2)};
			case ARM_REG_Q3:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q3)};
			case ARM_REG_Q4:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q4)};
			case ARM_REG_Q5:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q5)};
			case ARM_REG_Q6:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q6)};
			case ARM_REG_Q7:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q7)};
			case ARM_REG_Q8:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q8)};
			case ARM_REG_Q9:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q9)};
			case ARM_REG_Q10:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q10)};
			case ARM_REG_Q11:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q11)};
			case ARM_REG_Q12:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q12)};
			case ARM_REG_Q13:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q13)};
			case ARM_REG_Q14:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q14)};
			case ARM_REG_Q15:
				return {op_type::vpr_q, static_cast<s32>(cpu::vpr_q::q15)};
			//gpr
			case ARM_REG_R0:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r0)};
			case ARM_REG_R1:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r1)};
			case ARM_REG_R2:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r2)};
			case ARM_REG_R3:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r3)};
			case ARM_REG_R4:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r4)};
			case ARM_REG_R5:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r5)};
			case ARM_REG_R6:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r6)};
			case ARM_REG_R7:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r7)};
			case ARM_REG_R8:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r8)};
			case ARM_REG_R9:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r9)};
			case ARM_REG_R10:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r10)};
			case ARM_REG_R11:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r11)};
			case ARM_REG_R12:
				return {op_type::gpr, static_cast<s32>(cpu::reg::r12)};
			case ARM_REG_SP:
				return {op_type::gpr, static_cast<s32>(cpu::reg::sp)};
			case ARM_REG_LR:
				return {op_type::gpr, static_cast<s32>(cpu::reg::lr)};
			case ARM_REG_PC:
				return {op_type::gpr, static_cast<s32>(cpu::reg::pc)};

			case ARM_REG_S0:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s0)};
			case ARM_REG_S1:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s1)};
			case ARM_REG_S2:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s2)};
			case ARM_REG_S3:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s3)};
			case ARM_REG_S4:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s4)};
			case ARM_REG_S5:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s5)};
			case ARM_REG_S6:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s6)};
			case ARM_REG_S7:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s7)};
			case ARM_REG_S8:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s8)};
			case ARM_REG_S9:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s9)};
			case ARM_REG_S10:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s10)};
			case ARM_REG_S11:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s11)};
			case ARM_REG_S12:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s12)};
			case ARM_REG_S13:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s13)};
			case ARM_REG_S14:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s14)};
			case ARM_REG_S15:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s15)};
			case ARM_REG_S16:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s16)};
			case ARM_REG_S17:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s17)};
			case ARM_REG_S18:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s18)};
			case ARM_REG_S19:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s19)};
			case ARM_REG_S20:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s20)};
			case ARM_REG_S21:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s21)};
			case ARM_REG_S22:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s22)};
			case ARM_REG_S23:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s23)};
			case ARM_REG_S24:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s24)};
			case ARM_REG_S25:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s25)};
			case ARM_REG_S26:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s26)};
			case ARM_REG_S27:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s27)};
			case ARM_REG_S28:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s28)};
			case ARM_REG_S29:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s29)};
			case ARM_REG_S30:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s30)};
			case ARM_REG_S31:
				return {op_type::vpr_s, static_cast<s32>(cpu::vpr_s::s31)};
			}
			using ret_t = std::pair<operand::op_type, s32>;

			std::cout << "capstone/arm.h: " << 253 + cs_reg << '\n';
			return UNREACHABLE(ret_t);

	}

	void getShift(operand::box_val& op, cs_arm_op& cs_op) {
		using operand::modifier_type;

		switch(cs_op.shift.type) {
			case ARM_SFT_INVALID:
				op.mod = modifier_type::empty;
				return;

			case ARM_SFT_ASR:
				op.mod = modifier_type::asr_imm;
				op.mod1 = static_cast<s32>(cs_op.shift.value);
				return;
			case ARM_SFT_LSL:
				op.mod = modifier_type::lsl_imm;
				op.mod1 = static_cast<s32>(cs_op.shift.value);
				return;
			case ARM_SFT_LSR:
				op.mod = modifier_type::lsr_imm;
				op.mod1 = static_cast<s32>(cs_op.shift.value);
				return;
			case ARM_SFT_ROR:
				op.mod = modifier_type::ror_imm;
				op.mod1 = static_cast<s32>(cs_op.shift.value);
				return;
			case ARM_SFT_RRX:
				op.mod = modifier_type::rrx_imm;
				op.mod1 = static_cast<s32>(cs_op.shift.value);
				return;

			//Implicetly assuming cpu::reg::r0 - cpu::reg::r15 are
			//represented by the corresponding values  0 - 15
			case ARM_SFT_ASR_REG:
				op.mod = modifier_type::asr_reg;
				op.mod1 = resolveCSRegister(static_cast<s32>(cs_op.shift.value)).second;
				return;
			case ARM_SFT_LSL_REG:
				op.mod = modifier_type::lsl_reg;
				op.mod1 = resolveCSRegister(static_cast<s32>(cs_op.shift.value)).second;
				return;
			case ARM_SFT_LSR_REG:
				op.mod = modifier_type::lsr_reg;
				op.mod1 = resolveCSRegister(static_cast<s32>(cs_op.shift.value)).second;
				return;
			case ARM_SFT_ROR_REG:
				op.mod = modifier_type::ror_reg;
				op.mod1 = resolveCSRegister(static_cast<s32>(cs_op.shift.value)).second;
				return;
			case ARM_SFT_RRX_REG:
				op.mod = modifier_type::rrx_reg;
				op.mod1 = resolveCSRegister(static_cast<s32>(cs_op.shift.value)).second;
				return;
		}
	}

	void resolveCSMem(operand::box_val& op, cs_arm_op& cs_op) {
		using operand::op_type;
		using operand::modifier_type;


		op.type = op_type::mem;
		op.val = resolveCSRegister(cs_op.mem.base).second;

		auto[ind_type, ind_val] = resolveCSRegister(cs_op.mem.index);
		if(ind_type == op_type::empty && cs_op.mem.disp == 0) {
		//   index reg is not used       //no displacement
			//no index reg or displacement, so done parsing memory
			op.mod = modifier_type::empty;
			return;
		}

		if(ind_type == op_type::empty) {
			//case for immediate offset;
			op.mod = modifier_type::offset;
			op.mod1 = cs_op.mem.disp;
			return;
		}

		//register (shifted) index

		if(op.mod != modifier_type::empty) {
			//there is a shift that needs to be accounted for
			op.mod2 = op.mod1;
			op.mod = [old_mod = op.mod]() {
				switch(old_mod) {
					case modifier_type::asr_imm:
						return modifier_type::index_asr;
					case modifier_type::lsl_imm:
						return modifier_type::index_lsl;
					case modifier_type::lsr_imm:
						return modifier_type::index_lsr;
					case modifier_type::ror_imm:
						return modifier_type::index_ror;
					case modifier_type::rrx_imm:
						return modifier_type::index_rrx;
					default: break;
				}
						FATAL("invalid modifier type, {}",old_mod);
						return UNREACHABLE(modifier_type);
			}(); //IIFE to keep the UNREACHABLE symantics
		} else {
			op.mod = modifier_type::index;
		}

		op.mod1 = resolveCSRegister(cs_op.mem.index).second;

	}

	operand::box_val boxOperand(cs_arm_op& cs_op) {
		using operand::op_type;
		using operand::modifier_type;

		operand::box_val op;

		//should alrady be the value from the default
		//ctor above, but just ensuring it for resolveCSMem
		op.mod = modifier_type::empty;

		op.negate = cs_op.subtracted;

		getShift(op, cs_op);

		switch(cs_op.type) {
			case ARM_OP_INVALID :
				op.type = op_type::empty;
				break;
			case ARM_OP_REG:
				std::tie(op.type, op.val) = resolveCSRegister(cs_op.reg);
				break;
			case ARM_OP_IMM:
				op.type = op_type::imm;	op.val = cs_op.imm;
				break;
			case ARM_OP_MEM:
				resolveCSMem(op, cs_op);
				break;
			case ARM_OP_FP:
				op.type = op_type::empty;
				break;
			case ARM_OP_CIMM:
				op.type = op_type::cimm; op.val = cs_op.imm;
				break;
			case ARM_OP_PIMM:
				op.type = op_type::pimm; op.val = cs_op.imm;
				break;
			case ARM_OP_SETEND:
				op.type = op_type::empty;
				break;
			case ARM_OP_SYSREG:
				op.type = op_type::empty;
				break;
		}

		return op;
	}

	operand::box_val filterOp(cs_insn *cs_insn, const operand::box_val& in_box){
		using operand::op_type;
		using operand::modifier_type;

		operand::box_val box = in_box;

		//mark the registers to be used as user mode instead of active bank
		if(box.type == op_type::gpr && cs_insn->detail->arm.usermode) {
			box.type = op_type::user_gpr;
		}

		//adjust fix pc fixed rel to be a fixed address
		if(box.type == op_type::mem && box.val == static_cast<s32>(cpu::reg::pc) 
			&& (box.mod == modifier_type::empty || box.mod == modifier_type::offset))
		{
			addr_t pc = static_cast<addr_t>(cs_insn->address);
			//adjust for the fact that the pc is 2 instruction fetches
			//above the currenlty executing isntruction
			if(pc & 1) {
				pc += 2 * fetch_size<isa::thumb>;
			} else {
				pc += 2 * fetch_size<isa::arm>;
			}

			addr_t addr = pc;
			if(box.mod == modifier_type::offset) {
				addr += static_cast<addr_t>(box.mod1);
			}

			box.type = op_type::addr;
			box.val = static_cast<s32>(addr);
			box.mod = modifier_type::empty;
			//for tidyness and sanity, probably not needed
			box.mod1 = 0;
			box.mod2 = 0;
		}

		//adjust tag for branching operand if needed
		if(cs_insn->id == ARM_INS_B || cs_insn->id == ARM_INS_BL ||
			(cs_insn->id == ARM_INS_BLX && box.type == op_type::imm))
		{
			// Branch(potentially with link)(potentially with exchange) with an
			// immediate should be treated as an address as capstone will 
			// auto translate it to the address, just need to update the tag
			box.type = op_type::addr;
		}

		return box;
	}

	//so far only used for the regListCompressIndex function, might be used elsewhere
	using rl_pair = std::pair<arm_insn, s8>;

	constexpr int regListCompressIndex(arm_insn id) {
		switch(id) {
			case ARM_INS_LDMDA: 
			case ARM_INS_LDMDB: 
			case ARM_INS_LDM: 
			case ARM_INS_LDMIB: 

			case ARM_INS_STMDA:
			case ARM_INS_STMDB:
			case ARM_INS_STM:
			case ARM_INS_STMIB:

			case ARM_INS_VLDMDB:
			case ARM_INS_VLDMIA:

			case ARM_INS_VSTMDB:
			case ARM_INS_VSTMIA:

				return 1;
			//---------------------
			case ARM_INS_POP:
			case ARM_INS_PUSH:
			
			case ARM_INS_VPUSH:
			case ARM_INS_VPOP:

				return 0;
			//---------------------
			default:
				return -1;

		}		
	}

	operandList regListCompress(int index, const operandList& in_list) {
		using operand::op_type;
		operandList list{};

		auto in_begin = in_list.begin();
		auto in_index = in_list.begin(); std::advance(in_index, index);
		auto in_end   = in_list.end();

		//reglist will always be the last operand, this will 
		//copy any operands before the reglist. Currently
		//this will just be either 0 or 1 elements, but this
		//allows for it to be larger later on for some potential
		//optimization in the future or w/e
		if(index) {
			std::copy(in_begin, in_index, std::back_inserter(list));
		}
		
		operand::box_val regList;
		regList.type = op_type::reglist;
		std::for_each(in_index, in_end, [&rlist = regList.val] (operand::box_val reg) mutable {
			//TODO: replace this string with a more descriptive exception
			if(reg.type == op_type::gpr || reg.type == op_type::user_gpr
				|| reg.type == op_type::vpr_s || reg.type == op_type::vpr_d || reg.type == op_type::vpr_q)
			{
				rlist |= (1 << reg.val);
			} else {

				CRITICAL("Malformed instruction. Attempt to use a nonregister in a reglist\n with op={}", reg);
				throw "trying to form reglist with a non register";
			}
		});

		list.push_back(regList);

		return list;
	}

	operand::operand_t translateOpList(cs_insn *cs_ins, operandList in_list) {
		operand::operand_t ret;

		if(int index = regListCompressIndex(static_cast<arm_insn>(cs_ins->id)); index != -1){
			in_list = regListCompress(index, in_list);
		}

		std::copy(in_list.begin(), in_list.end(), std::back_inserter(ret));

		return ret;
	}

	operand::operand_t decodeOperand(cs_insn *cs_ins) {
		operandList op_list;

		cs_arm& arm = cs_ins->detail->arm;

		for(int i = 0; i < arm.op_count; i++){
			cs_arm_op& cs_op = arm.operands[i];
			operand::box_val box = boxOperand(cs_op);
			op_list.push_back(filterOp(cs_ins, box));
		}

		return translateOpList(cs_ins, op_list);//
	}

	template<>
	ins_t decode<isa::arm>(cs_insn *ins) {
		//printInfo(ins);

		ins_t decoded;

		decoded.addr = static_cast<addr_t>(ins->address);

		for(int size = ins->size, i = 0; i < size; i++) {
			decoded.raw |= static_cast<u32>(ins->bytes[i] << (8 * i));
		}

		decoded.cond = csCondToAtl(ins->detail->arm.cc);
		decoded.op = csOpToAtl(ins->id);
		decoded.operands = decodeOperand(ins);

		//printInst(decoded);	

		Log::Logger::get().flush();	

		return decoded;
	}

	template<>
	ins_t decode<isa::thumb>(cs_insn *ins) {
		ins_t decoded;

		DEBUG("Thumb Decoding: \t{:08x}\t{}  {}", ins->address, ins->mnemonic, ins->op_str);
		
		return decoded;
	}


} //namespace arm

namespace fmt {
	template<>
	struct formatter<cs_arm_op> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const cs_arm_op &op, FormatContext &ctx) {

			switch(op.type) {
				case ARM_OP_INVALID:
					return format_to(ctx.out(), "invalid operand");
				case ARM_OP_REG:
					if(op.shift.type == ARM_SFT_INVALID)
						return format_to(ctx.out(), "reg: {}", arm::csRegToStr(op.reg));
					else if(arm::isRegShift(op.shift.type))
						return format_to(ctx.out(), "reg: {} {} {}", arm::csRegToStr(op.reg), 
							arm::csShiftToStr(op.shift.type), arm::csRegToStr(static_cast<int>(op.shift.value)));
					else
						return format_to(ctx.out(), "reg: {} {} {}", arm::csRegToStr(op.reg), 
							arm::csShiftToStr(op.shift.type), op.shift.value);
				case ARM_OP_IMM:
					return format_to(ctx.out(), "imm: 0x{:x}", op.imm);
				case ARM_OP_MEM:
					return format_to(ctx.out(), 
	R"(mem:
	{{
	base	: {}
	index	: {}
	scale	: {}
	disp	: {}
	lshift	: {}
	}}
shiftt	: {}
shiftv	: {})", arm::csRegToStr(op.mem.base), arm::csRegToStr(op.mem.index), op.mem.scale, 
	op.mem.disp, op.mem.lshift, arm::csShiftToStr(op.shift.type), op.shift.value);
				case ARM_OP_FP:
					return format_to(ctx.out(), "fp imm", op.fp);
				case ARM_OP_CIMM:
					return format_to(ctx.out(), "cimm: {}", op.imm);
				case ARM_OP_PIMM:
					return format_to(ctx.out(), "pimm: {}", op.imm);
				case ARM_OP_SETEND:
					return format_to(ctx.out(), "setend: {}", (op.setend == ARM_SETEND_BE) ? "be" : "le");
				case ARM_OP_SYSREG:
					return format_to(ctx.out(), "sysreg: {}", op.reg);
			}

			return UNREACHABLE(decltype(format_to(ctx.out(), "")));
		}
	};

	template<>
	struct formatter<arm::operand::box_val> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const arm::operand::box_val &box, FormatContext &ctx) {
			using arm::operand::op_type;
			using arm::operand::modifier_type;
			auto it = ctx.out();
			auto fmt = [&](auto... args) {
				it = format_to(it, args...);
				it = format_to(it, " ");
			};

			auto signChar = [sign = (box.negate == false)] {
				if(sign)
					return '+';
				else
					return '-';
			};

			switch(box.type) {
				case op_type::empty:
					fmt("empty");
					break;
				case op_type::mem:
					fmt("box::mem [ {}", static_cast<arm::cpu::reg>(box.val));

					if(box.mod == modifier_type::empty)
						fmt("]");

					break;
				case op_type::imm:
					fmt("box::imm: {:x}", box.val); 
					break;
				case op_type::gpr:
					fmt("box::{}", static_cast<arm::cpu::reg>(box.val)); 
					break;
				case op_type::user_gpr:
					fmt("box::u{}", static_cast<arm::cpu::reg>(box.val)); 
					break;
				case op_type::vpr_s:
					fmt("box::vpr_s::s{}", box.val); 
					break;
				case op_type::vpr_d:
					fmt("box::vpr_d::d{}", box.val); 
					break;
				case op_type::vpr_q:
					fmt("box::vpr_q::q{}", box.val); 
					break;
				case op_type::psr:
					fmt("box::psr::{}", getPsrName(static_cast<arm::cpu::sr>(box.val)));
					break;
				case op_type::addr:
					fmt("box::addr::{:08x}", static_cast<addr_t>(box.val));
					break;
				case op_type::pimm:
					fmt("box::pimm::{}", box.val);
					break;
				case op_type::cimm:
					fmt("box::cimm::{}", box.val);
					break;
				default:
					fmt("unknown box type: {}", static_cast<u32>(box.type));
			}
			switch(box.mod) {
				case modifier_type::empty:
					break;
				case modifier_type::asr_imm:
				case modifier_type::lsl_imm:
				case modifier_type::lsr_imm:
				case modifier_type::ror_imm:
				case modifier_type::rrx_imm:
					fmt("{} {}", box.mod, box.mod1);
					break;

				case modifier_type::asr_reg:
				case modifier_type::lsl_reg:
				case modifier_type::lsr_reg:
				case modifier_type::ror_reg:
				case modifier_type::rrx_reg:
					fmt("{} {}", box.mod, static_cast<arm::cpu::reg>(box.mod1));
					break;
				
				case modifier_type::offset:
					fmt("{} {} ]", signChar(), box.mod1);
					break;

				case modifier_type::index:
					fmt("{} {} ]", signChar(), static_cast<arm::cpu::reg>(box.mod1));
					break;

				case modifier_type::index_asr:
				case modifier_type::index_lsl:
				case modifier_type::index_lsr:
				case modifier_type::index_ror:
				case modifier_type::index_rrx:
					fmt("{} {} {} {} ]", signChar(), static_cast<arm::cpu::reg>(box.mod1), box.mod, box.mod2);
					break;
			}

			return it;			
		}
	};

	template<>
	struct formatter<arm::operand::modifier_type> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const arm::operand::modifier_type &mod, FormatContext &ctx) {
			#define toStr(x) case arm::operand::modifier_type::x : return format_to(ctx.out(), #x)
			switch(mod) {
				case arm::operand::modifier_type::asr_imm:
				case arm::operand::modifier_type::asr_reg:
				return format_to(ctx.out(), "asr");

				case arm::operand::modifier_type::lsl_imm:
				case arm::operand::modifier_type::lsl_reg:
				return format_to(ctx.out(), "lsl");
				
				case arm::operand::modifier_type::ror_imm:
				case arm::operand::modifier_type::ror_reg:
				return format_to(ctx.out(), "ror");
				
				case arm::operand::modifier_type::lsr_imm:
				case arm::operand::modifier_type::lsr_reg:
				return format_to(ctx.out(), "lsr");
				
				case arm::operand::modifier_type::rrx_imm:
				case arm::operand::modifier_type::rrx_reg:
				return format_to(ctx.out(), "rrx");
				
				toStr(empty);
				toStr(offset);
				toStr(index);
				toStr(index_asr);
				toStr(index_lsl);
				toStr(index_lsr);
				toStr(index_ror);
				toStr(index_rrx);
			}
			return ctx.out();
			#undef toStr
		}
	};

}//namespace fmt