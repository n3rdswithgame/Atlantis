#ifndef ARM_H
#define ARM_H

//handles ARM + Thumb even though its named just arm

//TODO: figure out how to remove the "core/" in these headers

#include "core/ast/ast.h"
#include "core/cpu.h"
#include "core/mmu.h"

#include <string_view>

#include <capstone/capstone.h>

namespace arm {

	enum class isa {
		arm,
		thumb,
	};

	enum class cond : u8 {
		//taken straight form the ARM Archatecture Reference Manual

							// meaning								flags

		EQ = 0b0000, 		// Equal 								Z set
		NE = 0b0001, 		// Not equal 							Z clear
		CS = 0b0010, 		// Carry set/unsigned higher or same 	C set
		CC = 0b0011, 		// Carry clear/unsigned lower 			C clear
		MI = 0b0100, 		// Minus/negative 						N set
		PL = 0b0101, 		// Plus/positive or zero 				N clear
		VS = 0b0110, 		// Overflow 							V set
		VC = 0b0111, 		// No overflow 							V clear
		HI = 0b1000, 		// Unsigned higher 						C set and Z clear
		LS = 0b1001, 		// Unsigned lower or same 				C clear or Z set
		GE = 0b1010, 		// Signed greater than or equal 		N set and V set, or N clear and V clear (N == V)
		LT = 0b1011, 		// Signed less than 					N set and V clear, or N clear and V set (N != V)
		GT = 0b1100, 		// Signed greater than 					Z clear, and either N set and V set, or N clear and V clear (Z == 0,N == V)
		LE = 0b1101, 		// Signed less than or equal 			Z set, or N set and V clear, or N clear and V set (Z == 1 or N != V)
		AL = 0b1110, 		// Always (unconditional) -

		// the invalid conditional is only used on instructions that can't be conditional,
		// so in the lifter those will just be tagged as AL

		HS = CS,
		LO = CC,
	};

	enum class mnemonics {
		// basic instruction for now just so the enum
		// isn't empty. Will add more once I get the 
		// lifter working and can start testing 

		add,
		sub,
		mul,

		ldb,
		ldh,
		ldw,

		stb,
		sth,
		stw,

		mov,
		cmp,
		b,
	};

	//TODO: consider going back to variant
	
	enum class operand_type {
		u_imm,				//unsigned immediate
		s_imm,				//  signed immediate
		gpr,				//general purpose reg
		psr,				//program status reg
		cpr,				//coprocessor reg
		vpr,				//vector reg
		address,			//address
	};

	struct operand_t {
		operand_type	type;
		reg_t			val;
	};

	struct arm_ins_t {
		addr_t 					addr;
		arm::cond				cond;
		mnemonics	 			op;
		std::vector<operand_t>	operands;
	};

	using basic_block			= ast::bb::bb_t<arm_ins_t, isa>;
	using basic_block_tracker	= ast::bb::tracker_t<arm_ins_t, isa>;

	void decodeArm(arm_ins_t& ins, std::string_view mnemonic, std::string_view op_str);
	void decodeThumb(arm_ins_t& ins, std::string_view mnemonic, std::string_view op);

	template<typename Region>
	class Lifter : ast::Lifter<arm_ins_t, isa, Lifter<Region>, mmu::mmu<Region>> {

		using ast_Lifter = ast::Lifter<arm_ins_t, isa, Lifter<Region>, mmu::mmu<Region>>;
		
		//TODO: Profile 2 different capstone instances
		//vs 1 and switching the isa as needed
		csh cap_arm;
		csh cap_thumb;


	public:
		Lifter(const mmu::mmu<Region> &m) : ast_Lifter(m) {
			if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cap_arm);
				ret != CS_ERR_OK) {
				FATAL("Error creating ARM capstone engine with error code: {}", ret);
			}
			if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &cap_thumb);
				ret != CS_ERR_OK) {
				FATAL("Error creating THUMB capstone engine with error code: {}", ret);
			}
		}

		Lifter(Lifter&& l) {
			cap_arm   = l.cap_arm;
			cap_thumb = l.cap_thumb;
		}

		~Lifter() {
			if(ast_Lifter::isValid()) {
				cs_close(&cap_arm);
				cs_close(&cap_thumb);
			}
		}

	private:
		arm_ins_t fetch_impl(addr_t pc) {
			if((pc & 1) == 0)
				return fetchArm_impl(pc);
			else
				return fetchThumb_impl(pc & (~1U)); // translate pc into address
		}
		
		arm_ins_t fetchArm_impl(addr_t addr) {
			return fetchArch_impl<isa::arm>(addr);
		}

		arm_ins_t fetchThumb_impl(addr_t addr) {
			//pc is already translated into an address in fetch_impl
			return fetchArch_impl<isa::thumb>(addr);
		}
		
		template<isa i>
		arm_ins_t fetchArch_impl(addr_t addr) {
			constexpr size_t num_inst = 1;
			constexpr bool is_arm = (i == isa::arm);
	
			cs_insn *insn;
			size_t count;
	
			u32 raw_machine_code; //for the log message
			if constexpr(is_arm) {
				u32 machine_code = ast_Lifter::template mmuFetch<u32>(addr).read_val;//no static_cast as read_val is already a reg_t aka u32
				raw_machine_code = machine_code;
				count = cs_disasm(cap_arm, reinterpret_cast<u8*>(&machine_code),
					sizeof(machine_code), addr, num_inst, &insn);
			} else {
				u16 machine_code = static_cast<u16>(ast_Lifter::template mmuFetch<u16>(addr).read_val);
				raw_machine_code = machine_code;
				count = cs_disasm(cap_thumb, reinterpret_cast<u8*>(&machine_code),
					sizeof(machine_code), addr, num_inst, &insn);
			}
	
			if (count == 0) {
				FATAL("Failure to disassemble {0} machine code into instructions\n"
					  "\taddr: 0x{1:08x}\n"
					  "\t raw: 0x{2:08x}",
					  i,
					  addr,
					  raw_machine_code);
				return {};
			}
	
			arm_ins_t ins{};
			ins.addr = addr;
	
			if constexpr(is_arm) {
				decodeArm(ins, insn[0].mnemonic, insn[0].op_str);
			} else {
				decodeThumb(ins, insn[0].mnemonic, insn[0].op_str);
			}
	
			cs_free(insn, num_inst);
	
			return ins;
		}
	};
} //namespace arm

namespace fmt {
	template<>
	struct formatter<arm::isa> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const arm::isa &isa, FormatContext &ctx) {

			switch(isa) {
				case arm::isa::arm:
					return format_to(ctx.begin(), "isa::arm");
				case arm::isa::thumb:
					return format_to(ctx.begin(), "isa::thumb");
			}

			return UNREACHABLE(decltype(format_to(ctx.begin(), "")));

			#undef ignore
		}		
	};
}//namespace fmt

#endif //ARM_H