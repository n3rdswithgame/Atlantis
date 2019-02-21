#ifndef CPU_H
#define CPU_H

#include "common/logger.h"
#include "common/unreachable.h"
#include "common/types.h"

#include <array>
#include <string>

#include <fmt/format.h> //silence error on formatter if its not included


#define BIT(x) (1U << unsigned(x))

namespace arm::cpu {

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
				return 0b10000; //0x10
			case fiq:
				return 0b10001; //0x11
			case irq:
				return 0b10010; //0x12
			case svc:
				return 0b10011; //0x13
			case abt:
				return 0b10111; //0x17
			case sys:
				return 0b11111; //0x1F
			case und:
				return 0b11011; //0x1B
			
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

	enum class vpr_s : u8 {
		s0,
		s1,
		s2,
		s3,
		s4,
		s5,
		s6,
		s7,
		s8,
		s9,
		s10,
		s11,
		s12,
		s13,
		s14,
		s15,
		s16,
		s17,
		s18,
		s19,
		s20,
		s21,
		s22,
		s23,
		s24,
		s25,
		s26,
		s27,
		s28,
		s29,
		s30,
		s31,
	};

	enum class vpr_d : u8 {
		d0,
		d1,
		d2,
		d3,
		d4,
		d5,
		d6,
		d7,
		d8,
		d9,
		d10,
		d11,
		d12,
		d13,
		d14,
		d15,
		d16,
		d17,
		d18,
		d19,
		d20,
		d21,
		d22,
		d23,
		d24,
		d25,
		d26,
		d27,
		d28,
		d29,
		d30,
		d31,
	};

	enum class vpr_q : u8 {
		q0,
		q1,
		q2,
		q3,
		q4,
		q5,
		q6,
		q7,
		q8,
		q9,
		q10,
		q11,
		q12,
		q13,
		q14,
		q15
	};

	enum status_reg_masks : u32 {
		N 		= BIT(31),   //Negative
		Z 		= BIT(30),   //Zero
		C 		= BIT(29),   //Carry
		V 		= BIT(28),   //oVerflow

		I 		= BIT(7),
		F 		= BIT(6),
		T 		= BIT(5),

		MODE	= BIT(5) - 1
	};

	enum class sr : u8 {
		apsr,
		cpsr,
		spsr,
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

	constexpr const char* getPsrName(sr reg) {
		#define toStr(x)					\
		case sr::x:							\
			return #x
		#define ignore(x)					\
			case x: break;
		switch(reg) {
			toStr(apsr);
			toStr(cpsr);
			toStr(spsr);
		}
		return UNREACHABLE(char*);
		#undef toStr
		#undef ignore
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
	struct formatter<arm::cpu::reg> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const arm::cpu::reg &reg, FormatContext &ctx) {

			#define toStr(x)					\
			case arm::cpu::reg::x:					\
				return  format_to(ctx.out(), "reg::" #x)
			#define ignore(x)					\
				case arm::cpu::reg::x: break

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
			std::cout << static_cast<s32>(reg) << '\n';
			FATAL("invalid register {}", static_cast<s32>(reg));
			//return UNREACHABLE(decltype(format_to(ctx.out(), "")));
			return(ctx.out());
			#undef toStr
			#undef ignore
		}		
	};
}//namespace fmt

#undef BIT

#endif