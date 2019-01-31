#ifndef CPU_H
#define CPU_H

#include "common/unreachable.h"
#include "common/types.h"

#include <array>
#include <string>

#include <fmt/format.h> //silence error on formatter if its not included


#define BIT(x) (1U << unsigned(x))

namespace cpu {

	//typedef instead of a using to suppress a -Wsubobject-linkage warning on gcc and friends
	typedef enum {
		usr,
		fiq,
		irq,
		svc,
		abt,
		sys,
		und,

		mode_count
	} mode_t;

	//split the encoding between enum and constexpr function
	//since encodings are not contigious, and this way
	//switch statements on the mode can be a simple table

	constexpr unsigned modeToBits(mode_t mode) {
		switch(mode) {
			case usr:
				return 0b10000;
			case fiq:
				return 0b10001;
			case irq:
				return 0b10010;
			case svc:
				return 0b10011;
			case abt:
				return 0b10111;
			case sys:
				return 0b11111;
			case und:
				return 0b11011;
			
			case mode_count: break;
		}
		return UNREACHABLE(unsigned);
	}

	enum class reg : u8 { //banked, what the programmer uses / what is encoded
		r0,
		r1,
		r2,
		r3,
		r4,
		r5,
		r6,
		r7,
		r8,
		r9,
		r10,
		r11,
		r12,
		r13,
		r14,
		r15,

		reg_count,

		fp = r11,
		ip = r12, 
		sp = r13,
		lr = r14,
		pc = r15,
	};

	using gpr_t = enum : reg_t { //unbanked, what is "physically in the silicon"
		r0,
		r1,
		r2,
		r3,
		r4,
		r5,
		r6,
		r7,
		r8,
		r9,
		r10,
		r11,
		r12,
		r13,
		r14,
		r15,

		r8_fiq,
		r9_fiq,
		r10_fiq,
		r11_fiq,
		r12_fiq,
		r13_fiq,
		r14_fiq,

		r13_svc,
		r14_svc,

		r13_abt,
		r14_abt,

		r13_irq,
		r14_irq,

		r13_und,
		r14_und,

		gpr_count,
	};

	enum status_reg_masks : u32 {
		N 		= BIT(31),
		Z 		= BIT(30),
		C 		= BIT(29),
		V 		= BIT(28),

		I 		= BIT(7),
		F 		= BIT(6),
		T 		= BIT(5),

		MODE	= BIT(5) - 1
	};
	using psr_t = enum : reg_t{
		cspr,
		spsr_fiq,
		spsr_svc,
		spsr_abt,
		spsr_irq,
		spsr_und,

		psr_count
	};

	constexpr gpr_t unbankReg(mode_t mode, reg reg) {
		using register_bank_t = std::array<gpr_t, r15+1>;

		auto debanking_dispatch = [](mode_t m) -> register_bank_t {
			switch(m) {
				case usr:
				case sys:
					return {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13    , r14    , r15};
				case fiq:
					return {r0, r1, r2, r3, r4, r5, r6, r7, r8_fiq, r9_fiq, r10_fiq, r11_fiq, r12_fiq, r13_fiq, r14_fiq, r15};
				case svc:
					return {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_svc, r14_svc, r15};
				case abt:
					return {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_abt, r14_abt, r15};
				case irq:
					return {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_irq, r14_irq, r15};
				case und:
					return {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_und, r14_und, r15};
				case mode_count: break;
			}
			return UNREACHABLE(register_bank_t);
		};

		register_bank_t active_bank = debanking_dispatch(mode);

		return active_bank[static_cast<size_t>(reg)];
	}

	constexpr const char* getRegName(gpr_t reg) {
		#define toStr(x)					\
		case x:								\
			return #x
		#define ignore(x)					\
			case x: break;
		switch(reg) {
			toStr(r0);
			toStr(r1);
			toStr(r2);
			toStr(r3);
			toStr(r4);
			toStr(r5);
			toStr(r6);
			toStr(r7);
			toStr(r8);
			toStr(r9);
			toStr(r10);
			toStr(r11);
			toStr(r12);
			toStr(r13);
			toStr(r14);
			toStr(r15);

			toStr(r8_fiq);
			toStr(r9_fiq);
			toStr(r10_fiq);
			toStr(r11_fiq);
			toStr(r12_fiq);
			toStr(r13_fiq);
			toStr(r14_fiq);

			toStr(r13_svc);
			toStr(r14_svc);

			toStr(r13_abt);
			toStr(r14_abt);

			toStr(r13_irq);
			toStr(r14_irq);

			toStr(r13_und);
			toStr(r14_und);

			ignore(gpr_count)

		}
		return UNREACHABLE(char*);

		#undef ignore
		#undef toStr
	}

	struct state {
		std::array<reg_t,gpr_count> gpr = {};
		std::array<reg_t,psr_count> psr = {};

		mode_t current_mode = sys;
		u64 cycle = 0;

		reg_t& operator[](reg r) {
			return gpr[unbankReg(current_mode, r)];
		}
	};
}

namespace fmt {
	template<>
	struct formatter<cpu::reg> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const cpu::reg &reg, FormatContext &ctx) {

			#define toStr(x)					\
			case cpu::reg::x:					\
				return  format_to(ctx.begin(), "reg::" #x)
			#define ignore(x)					\
				case cpu::reg::x: break

			switch(reg) {
				toStr(r0 );
				toStr(r1 );
				toStr(r2 );
				toStr(r3 );
				toStr(r4 );
				toStr(r5 );
				toStr(r6 );
				toStr(r7 );
				toStr(r8 );
				toStr(r9 );
				toStr(r10);
				toStr(r11);
				toStr(r12);
				toStr(sp );
				toStr(lr );
				toStr(pc );

				ignore(reg_count);
			}

			return UNREACHABLE(decltype(format_to(ctx.begin(), "")));

			#undef toStr
			#undef ignore
		}		
	};
}//namespace fmt

#endif