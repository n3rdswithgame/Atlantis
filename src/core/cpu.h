#ifndef CPU_H
#define CPU_H

#include "common/unreachable.h"
#include "common/types.h"

#include <array>
#include <string>

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
			
			default:
				return UNREACHABLE(unsigned);
		}
	}

	using gpr_t = enum : reg_t {
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

		sp = r13,
		lr = r14,
		pc = r15,
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

	constexpr gpr_t unbankReg(mode_t mode, gpr_t reg) {
		std::array<gpr_t, r15+1> active_bank{};
		switch(mode) {
			case usr:
			case sys:
				active_bank = {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13    , r14    , r15};
				break;
			case fiq:
				active_bank = {r0, r1, r2, r3, r4, r5, r6, r7, r8_fiq, r9_fiq, r10_fiq, r11_fiq, r12_fiq, r13_fiq, r14_fiq, r15};
				break;
			case svc:
				active_bank = {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_svc, r14_svc, r15};
				break;
			case abt:
				active_bank = {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_abt, r14_abt, r15};
				break;
			case irq:
				active_bank = {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_irq, r14_irq, r15};
				break;
			case und:
				active_bank = {r0, r1, r2, r3, r4, r5, r6, r7, r8    , r9    , r10    , r11    , r12    , r13_und, r14_und, r15};
				break;

			default:
				active_bank = UNREACHABLE(decltype(active_bank));
		}

		return active_bank[reg];
	}

	constexpr const char* getRegName(gpr_t reg) {
		#define toStr(x)					\
		case x:								\
			return #x

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

			default:
				return UNREACHABLE(char*);
		}

		#undef toStr
	}

	struct state {
		std::array<reg_t,gpr_count> gpr = {};
		std::array<reg_t,psr_count> psr = {};

		mode_t current_mode = sys;
		u64 cycle = 0;

		reg_t& operator[](gpr_t r) {
			return gpr[unbankReg(current_mode, r)];
		}
	};
}

namespace fmt {
	//TODO: Figure out why gpr_t is formating like an int instead of using this formatter
	template<>
	struct formatter<cpu::gpr_t> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const cpu::gpr_t &reg, FormatContext &ctx) {
			return format_to(ctx.begin(), cpu::getRegName(reg));
		}		
	};
}//namespace fmt

#endif