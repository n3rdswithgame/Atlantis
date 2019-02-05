#ifndef ARM_H
#define ARM_H

//handles ARM + Thumb even though its named just arm

//TODO: figure out how to remove the "core/" in these headers

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