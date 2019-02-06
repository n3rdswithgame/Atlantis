#ifndef ARM_H
#define ARM_H

//handles ARM + Thumb even though its named just arm

//TODO: figure out how to remove the "core/" in these headers

#include "ins/ins.h"

#include "core/mmu.h"

#include <string_view>

#include <capstone/capstone.h>

namespace arm {

	enum class isa {
		arm,
		thumb,
	};

	using cond = ins::parts::cond;

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