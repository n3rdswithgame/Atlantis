#ifndef ARM_H
#define ARM_H

//handles ARM + Thumb even though its named just arm

//TODO: figure out how to remove the "core/" in these headers

#include "ins/ins.h"

#include "core/mmu.h"

#include <string_view>
#include <variant>

namespace arm {

	enum class isa {
		arm,
		thumb,
	};

	using cond = ::arm::ins::arm::parts::cond;

	enum class operation {
		// basic instruction for now just so the enum
		// isn't empty. Will add more once I get the 
		// lifter working and can start testing 

		//data_processing
		And,
		Eor,
		Sub,
		Rsb,
		Add,
		Adc,
		Sbc,
		Rsc,
		Tst,
		Teq,
		Cmp,
		Cmn,
		Orr,
		Mov,
		Bic,
		Mvn,

		B,
		Bl,

		Svc,

		undef,  //architectually undefined
		future, // instruction from a futre ARM isa //TODO:work this into the decoder
		unkn,   //unknown to the decoder
		count
	};

	//TODO: consider going back to variant
	
	namespace operand{
		struct rr_is { //register register immediate shift
			cpu::reg 			rd = cpu::reg::r0;
			cpu::reg 			rn = cpu::reg::r0;
			cpu::reg 			rm = cpu::reg::r0;
			u8				 shift = 0;
			arm_parts::shift  type = arm_parts::shift::lsl;
		};
		struct rr_rs {//register register register shift
			cpu::reg 		   rd = cpu::reg::r0;
			cpu::reg 		   rn = cpu::reg::r0;
			cpu::reg 		   rm = cpu::reg::r0;
			cpu::reg 		   rs = cpu::reg::r0;
			arm_parts::shift type = arm_parts::shift::lsl;
		};
		struct rr_ui {//register register immediate
			cpu::reg 		   rd = cpu::reg::r0;
			cpu::reg 		   rn = cpu::reg::r0;
			u32 			  imm = 0;
		};
		struct rr_si {//register register immediate
			cpu::reg 		   rd = cpu::reg::r0;
			cpu::reg 		   rn = cpu::reg::r0;
			s32 			  imm = 0;
		};
		struct ui {//unsigned immediate
			u32 			  imm = 0;
		};
		struct si {//signed immediate
			s32 			  imm = 0;
		};
		struct reglist {//register list
			u32 			  rl = 0;
		};

		using operand_t = std::variant<
							rr_is,
							rr_rs,
							rr_ui,
							rr_si,
							ui,
							si,
							reglist
						  >;
	} //namespace arm::oper

	struct ins_t {
		addr_t 					addr;
		u32						raw;
		arm::cond				cond;
		operation	 			op;
		operand::operand_t		operands;
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
					return format_to(ctx.out(), "isa::arm");
				case arm::isa::thumb:
					return format_to(ctx.out(), "isa::thumb");
			}

			return UNREACHABLE(decltype(format_to(ctx.out(), "")));

			#undef ignore
		}		
	};
}//namespace fmt

#endif //ARM_H