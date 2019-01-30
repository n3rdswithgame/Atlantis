#ifndef ARM_H
#define ARM_H

//handles ARM + Thumb even though its named just arm

#include "ast/ast.h"

namespace arm {

	enum class isa_t {
		arm,
		thumb,
	};

	enum class cond_t : u8 {
		//taken straight form the ARM Archatecture Reference Manual

							// meaning								flags

		EQ = 0b0000 		// Equal 								Z set
		NE = 0b0001 		// Not equal 							Z clear
		CS = 0b0010 		// Carry set/unsigned higher or same 	C set
		CC = 0b0011 		// Carry clear/unsigned lower 			C clear
		MI = 0b0100 		// Minus/negative 						N set
		PL = 0b0101 		// Plus/positive or zero 				N clear
		VS = 0b0110 		// Overflow 							V set
		VC = 0b0111 		// No overflow 							V clear
		HI = 0b1000 		// Unsigned higher 						C set and Z clear
		LS = 0b1001 		// Unsigned lower or same 				C clear or Z set
		GE = 0b1010 		// Signed greater than or equal 		N set and V set, or N clear and V clear (N == V)
		LT = 0b1011 		// Signed less than 					N set and V clear, or N clear and V set (N != V)
		GT = 0b1100 		// Signed greater than 					Z clear, and either N set and V set, or N clear and V clear (Z == 0,N == V)
		LE = 0b1101 		// Signed less than or equal 			Z set, or N set and V clear, or N clear and V set (Z == 1 or N != V)
		AL = 0b1110 		// Always (unconditional) -

		// the invalid conditional is only used on instructions that can't be conditional,
		// so in the lifter those will just be tagged as AL

		HS = CS,
		LO = CC,
	};

	enum class mnemonics_t {
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

	//TODO: not use variant
	//TODO: support coprocessor registers
	using operand_t = std::variant<s32, cpu::reg>;

	struct arm_ins_t {
		addr_t 					addr;
		cond_t 					cond;
		mnemonics_t 			op;
		std::vector<operand_t>	operands;
	};

	using basic_block			= ast::basic_block<arm_ins_t, isa_t>;
	using basic_block_tracker	= ast::basic_block_tracker<arm_inst_t, isa_t>;
} //namespace arm

#endif //ARM_H