#ifndef ENC_ARM_H
#define ENC_ARM_H

#include "common/types.h"

#include "core/cpu.h"

#include <type_traits>

#define REQUIRES_ARMv(n)	 //do nothing for now, eventually make it a failure
#define SHIFT(x, n)			((x) << (n))
#define BIT(n)				SHIFT(1,n)
#define LOWER(x,n)			((x) & (BIT(n) - 1))
#define BITPLACE(x,a,b)		(SHIFT(LOWER(x, b-a+1),a))
#define INST_UNIMP 			throw __func__ "is unimplemeted"
namespace arm::enc {
	constexpr u32 emit(addr_t, u32 val) {
		return val;
	}

	namespace op2 {

		struct imm {};
		struct reg {};

		enum class type { reg = 0, imm = BIT(25)};

		enum class shift {
			lsl = 0b00,
			lsr = 0b01,
			asl = 0b10,
			asr = 0b01,
		};

		constexpr u32 shiftRegByImm(u8 amnt, shift type) {
			u32 AMNT = BITPLACE(amt, 7, 11);
			u32 TYPE = BITPLACE(static_cast<u32>(type), 5, 6);
			u32 I    = SHIFT(0b0, 4);
			return AMNT | TYPE | I;
		}

		constexpr u32 shiftRegByReg(cpu::reg rs, shift type) {
			u32 RS   = BITPLACE(static_cast<u32>(rs), 8, 11);
			u32 TYPE = BITPLACE(static_cast<u32>(type), 5, 6);
			u32 R    = SHIFT(0b0, 7) | SHIFT(0b1, 4);
			return RS | TYPE | R;
		}

		constexpr u32 reg(cpu::reg rm, shift s, cpu::reg rs) {
			u32 TYPE  = static_cast<u32>(type::reg)
			u32 RM = static_cast<u32>(RM);
			u32 Shift = shiftRegByReg(rs, s);
			return TYPE | Shift | RM;
		}

		constexpr u32 reg(cpu::reg rm, shift type, u8 amnt) {
			u32 RM    = static_cast<u32>(RM);
			u32 Shift = shiftRegByImm(amnt, type);
			return Shift | RM;
		}

		constexpr u32 encodeImm(u8 rot, u8 imm) {
			u32 ROT  = BITPLACE(rot, 8, 11);
			u32 IMM  = static_cast<u32>(imm);
			return ROT | IMM;
		}

		constexpr u32 imm(u32 imm) {
			u32 rot = 0;
			u32 imm = 0;

			//TODO: logic

			return encodeImm(rot, imm);
		}

	} //namespace op2

	enum class op : u32 {
		dataProcessing		= SHIFT(   0b001, 25),
		mul					= SHIFT(0b000000, 22) | SHIFT(0b1001, 4),
		mul_long			= SHIFT( 0b00001, 23) | SHIFT(0b1001, 4),
		sw_swap				= SHIFT( 0b00010, 20) | SHIFT(  0b00, 20) | SHIFT(0b00001001, 4),
		bx					= SHIFT(  0b000100101111111111110001, 4),
		hword_dt_ro			= SHIFT(   0b000, 25) | SHIFT(   0b0, 22) | SHIFT(   0b00001, 7) | SHIFT(0b1, 4),
		hword_dt_io			= SHIFT(   0b000, 25) | SHIFT(   0b1, 22) | SHIFT(       0b1, 7) | SHIFT(0b1, 4),
		sw_trans			= SHIFT(    0b01, 26),
		undef				= SHIFT(   0b011, 25) | SHIFT(   0b1, 4),
		block_data_trans	= SHIFT(   0b100, 25),
		b					= SHIFT(   0b101, 25),
		co_dt				= SHIFT(   0b110, 25),
		co_do				= SHIFT(  0b1110, 24) | SHIFT(0b0, 4),
		co_rt				= SHIFT(  0b1110, 24) | SHIFT(0b1, 4),
		svc					= SHIFT(  0b1111, 24)
	};

	enum class flags : u32{ignore = 0, update = BIT(20)};

	enum class data_processing : u32 {
		and		= BITPLACE(0b0000, 21, 24),
		eor		= BITPLACE(0b0001, 21, 24),
		sub		= BITPLACE(0b0010, 21, 24),
		rsub	= BITPLACE(0b0011, 21, 24),
		add		= BITPLACE(0b0100, 21, 24),
		adc		= BITPLACE(0b0101, 21, 24),
		sbc		= BITPLACE(0b0110, 21, 24),
		rsc		= BITPLACE(0b0111, 21, 24),
		tst		= BITPLACE(0b1000, 21, 24),
		teq		= BITPLACE(0b1001, 21, 24),
		cmp		= BITPLACE(0b1010, 21, 24),
		cmn		= BITPLACE(0b1011, 21, 24),
		orr		= BITPLACE(0b1100, 21, 24),
		mov		= BITPLACE(0b1101, 21, 24),
		bic		= BITPLACE(0b1110, 21, 24),
		mvn		= BITPLACE(0b1111, 21, 24),
	};
	
	constexpr u32 dataProcessing(addr_t addr, op2::type i, data_processing op, flags s, cpu::reg rn, cpu::reg rd, u32 op2) {
		u32 I  = static_cast<u32>(i);
		u32 DP = static_cast<u32>(op::dataProcessing);
		u32 OP = static_cast<u32>(op);
		u32 S  = static_cast<u32>(s);
		u32 RN = SHIFT(static_cast<u32>(rn), 16);
		u32 RD = SHIFT(static_cast<u32>(rd), 12);
		return emit(addr, I | OP | DP | S | RN | RD | op2 );
	}

	constexpr u32 dataProcessing(addr_t addr, data_processing op, flags s, cpu::reg rn, cpu::reg rd, cpu::reg rm, shift s, cpu::reg rs) {
		return dataProcessing(addr, op2::type::reg, op, s, rn, rd, op2::reg(rm, s, rs));
	}

	constexpr u32 dataProcessing(addr_t addr, data_processing op, flags s, cpu::reg rn, cpu::reg rd, cpu::reg rm, shift type, u8 amnt) {
		return dataProcessing(addr, op2::type::reg, op, s, rn, rd, op2::reg(rm, s, amnt));
	}

	constexpr u32 dataProcessing(addr_t addr, data_processing op, flags s, cpu::reg rn, cpu::reg rd, u32 imm) {
		return dataProcessing(addr, op2::type::imm, op, s, rn, rd, op2::imm(imm));
	}

	enum class accumulate : u32 {multiple = 0, accumulate = BIT(21)};

	constexpr u32 multiply(addr_t addr, accumulate a, flags s, cpu::reg rd, cpu::reg rn, cpu::reg rs, cpu::reg rm) {
		u32 A	= static_cast<u32>(a)
		u32 MUL = static_cast<u32>(op::mul);
		u32 S	= static_cast<u32>(s)
		u32 RD	= BITPLACE(static_cast<u32>(rd), 16, 19);
		u32 RN	= BITPLACE(static_cast<u32>(rd), 12, 15);
		u32 RS	= BITPLACE(static_cast<u32>(rd),  8, 11);
		u32 RM	= BITPLACE(static_cast<u32>(rd),  0,  3);
		return emit(addr, A | MUL | S | RD | RN | RS | RM);
	}

	enum class unsigned_flag : u32 {u = 0, s = BIT(22)};

	constexpr u32 multiplyLong(addr_t addr, unsigned_flag u, accumulate a, flags s,
		cpu::reg rdhi, cpu::reg rdlo, cpu::reg rs, cpu::reg rm)
	{
		u32 MUL_LONG	= static_cast<u32>(op::mul_long);
		u32 U 			= static_cast<u32>(u);
		u32 A 			= static_cast<u32>(a);
		u32 S 			= static_cast<u32>(s);
		u32 RDHI 		= BITPLACE(static_cast<u32>(rdhi), 16, 19);
		u32 RDLO 		= BITPLACE(static_cast<u32>(rdlo), 12, 15);
		u32 RS 			= BITPLACE(static_cast<u32>(rs  ),  8, 11);
		u32 RM 			= BITPLACE(static_cast<u32>(rm  ),  0,  3);
		return emit(addr, MUL_LONG | U | A | S | RDHI | RDLO | RS | RM);
	}

	enum class sd_size : u32 { word = 0, byte = BIT(22)};

	constexpr u32 sw_swap(addr_t addr, sd_size b, cpu::reg rn, cpu::reg rd, cpu::reg rm) {
		u32 SW_SWAP 	= static_cast<u32>(op::sw_swap);
		u32 B			= static_cast<u32>(b);
		u32 RN			= BITPLACE(static_cast<u32>(rn), 16, 19);
		u32 RD			= BITPLACE(static_cast<u32>(rd), 12, 15);
		u32 RM			= BITPLACE(static_cast<u32>(rm),  0,  3);
		return emit(addr, SW_SWAP | B | RN | RD | RM);
	}

	constexpr u32 b_ex(addr_t addr, cpu::reg rn) { //this thunk is so BX can be with the other ops lower down
		u32 BX = static_cast<u32>(op::bx);
		u32 RN = BITPLACE(static_cast<u32>(rn), 0, 3);
		return emit(addr, BX | RN);
	}

	enum class indexing		: u32 {post   = 0, pre   = BIT(24)};
	enum class direction	: u32 {down   = 0, up    = BIT(23)};
	enum class write_back	: u32 {ignore = 0, write = BIT(21)};
	enum class memop		: u32 {store  = 0, load  = BIT(20)};
	enum class sh			: u32 {
		swp = 0,
		u16 = SHIFT(0b01, 5),
		s8  = SHIFT(0b10, 5),
		s16 = SHIFT(0b11, 5)
	};

	constexpr u32 hword_dt_ro(addr_t addr, indexing p, direction u, write_back w, memop L
		cpu::reg rn, cpu::reg rd, sh sh, cpu::reg rm)
	{
		u32 HWORD_DT_RO = static_cast<u32>(op::hword_dt_ro)
		u32 P			= static_cast<u32>(p);
		u32 U			= static_cast<u32>(u);
		u32 W			= static_cast<u32>(w);
		u32 L			= static_cast<u32>(l);
		u32 RN			= BITPLACE(static_cast<u32>(rn), 16, 19);
		u32 RD			= BITPLACE(static_cast<u32>(rd), 12, 15);
		u32 SH			= static_cast<u32>(sh);
		u32 RM			= BITPLACE(static_cast<u32>(rm),  0,  3);
		return emit(addr, HWORD_DT_RO | P | U | W | L | RN | RD | SH | RM);
	}

	constexpr u32 hword_dt_io(addr_t addr, indexing p, direction u, write_back w, memop L
		cpu::reg rn, cpu::reg rd, sh sh, u8 off)
	{
		u32 HWORD_DT_IO = static_cast<u32>(op::hword_dt_io)
		u32 P			= static_cast<u32>(p);
		u32 U			= static_cast<u32>(u);
		u32 W			= static_cast<u32>(w);
		u32 L			= static_cast<u32>(l);
		u32 RN			= BITPLACE(static_cast<u32>(rn), 16, 19);
		u32 RD			= BITPLACE(static_cast<u32>(rd), 12, 15);
		u32 SH			= static_cast<u32>(sh);
		u32 OFF_HI		= (static_cast<u32>(off) & 0xF0) << 4;
		u32 OFF_LO		= static_cast<u32>(off) & 0x0F;
		return emit(addr, HWORD_DT_RO | P | U | W | L | RN | RD | OFF_HI | SH | OFF_LO);
	}

	constexpr u32 sw_trans(addr_t addr, indexing p, direction u, sd_size b, write_back w, memop l,
		cpu::reg rn, cpu::reg rd, u32 op2)
	{
		u32 SW_TRANS	= static_cast<u32>(op::sw_trans);
		u32 P			= static_cast<u32>(p);
		u32 U			= static_cast<u32>(u);
		u32 B			= static_cast<u32>(b);
		u32 W			= static_cast<u32>(w);
		u32 L			= static_cast<u32>(l);
		u32 RN			= static_cast<u32>(rn);
		u32 RD			= static_cast<u32>(rd);
		u32 OP2			= static_cast<u32>(op2);
		return emit(addr, SW_TRANS | P | U | B | W | L | RN | RD | op2);
	}

	enum class status : u32 {ignore = 0, force_user}

	template<typename ... Regs>
	constexpr u32 block_data_trans(addr_t addr, indexing p, direction u, status s, write_back w, memop l,
		cpu::reg rn, Regs... reglist)
	{
		static_assert(std::is_same<decltype(reglist), cpu::reglist> && ...,
			"only cpu::reg allowed in the paramater pack");

		u32 BLOCK_DATA_TRANS	= static_cast<u32>(op::block_data_trans);
		u32 P					= static_cast<u32>(p)
		u32 U					= static_cast<u32>(u)
		u32 S					= static_cast<u32>(s)
		u32 W					= static_cast<u32>(w)
		u32 L					= static_cast<u32>(l)
		u32 RN					= static_cast<u32>(rn)
		u32 REGLIST				= BIT(static_cast<u32>(reglist)) | ...;
		return emit(addr, BLOCK_DATA_TRANS | P | U | S | W | L | RN | REGLIST);
	}

	enum class link : u32 {ignore = 0, link = BIT(24)};

	constexpr s32 addrToOff(addr_t addr, addr_t target) {
		s32 off = static_cast<s32>(target - (addr + 8)) >> 2;
		//Constants taken from ARM Archatecture Reference Manual
		//TODO: replace magic numbers with more expressive expression / macro
		if(off < −33554432 || 33554428 < off) 
			throw "unable to form branch instruction, target is outside of +- 32MB range";
		return off;
	}

	constexpr u32 branch(addr_t addr, link l, s32 rel) {
		u32 B   = static_cast<u32>(op::b);
		u32 L   = static_cast<u32>(l);
		u32 OFF = LOWER(static_cast<u32>(rel),24);
		return emit(addr, B | L | OFF);
	}

	constexpr u32 co_dt(addr_t addr) {
		INST_UNIMP;
	}

	constexpr u32 co_do(addr_t addr) {
		INST_UNIMP;
	}

	constexpr u32 co_rt(addr_t addr) {
		INST_UNIMP;
	}

	constexpr u32 svc_call(addr_t addr, u32 svc) {
		u32 SVC 	= static_cast<u32>(op::svc);
		u32 SVC_NUM = LOWER(svc, 24);

		return emit(addr, SVC | SVC_NUM);
	}



	template<typename... shifter>
	constexpr u32 adc(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::adc, flags::ignore, rn, rd, s_o...);
	}

	template<typename... shifter>
	constexpr u32 adc(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::adc, flags::update, rn, rd, s_o...);
	}

	template<typename... shifter>
	constexpr u32 add(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::add, flags::ignore, rn, rd, s_o...);
	}

	template<typename... shifter>
	constexpr u32 adds(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::add, flags::update, rn, rd, s_o...);
	}

	template<typename... shifter>
	constexpr u32 and(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::and, flags::ignore, rn, rd, s_o...);
	}

	template<typename... shifter>
	constexpr u32 ands(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::and, flags::update, rn, rd, s_o...);
	}

	constexpr u32 b(addr_t addr, addr_t target) {
		#REQUIRES_ARMv(1);
		return branch(addr, link::ignore, addrToOff(addr, target));
	}

	constexpr u32 bl(addr_t addr, addr_t target) {
		#REQUIRES_ARMv(1);
		return branch(addr, link::link, addrToOff(addr, target));
	}

	template<typename... shifter>
	constexpr u32 bic(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::bic, flags::ignore, rn, rd, s_o...);
	}

	template<typename... shifter>
	constexpr u32 bics(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::bic, flags::update, rn, rd, s_o...);
	}

	constexpr u32 bkpt(addr_t addr, u16 imm) {
		#REQUIRES_ARMv(1);
		INST_UNIMP;
	}

	constexpr u32 blx(addr_t addr, addr_t target) {
		#REQUIRES_ARMv(5);
		INST_UNIMP;
	}

	constexpr u32 blx(addr_t addr, cpu::reg rm) {
		#REQUIRES_ARMv(5);
		INST_UNIMP;
	}

	constexpr u32 bx(addr_t addr, cpu::reg rm) {
		#REQUIRES_ARMv(1);
		return b_ex(addr, rm);
	}

	constexpr u32 bxj(addr_t addr, cpu::reg rm) {
		REQUIRES_ARMv(6);
		INST_UNIMP;
	}

	constexpr u32 cdp(addr_t addr) {
		REQUIRES_ARMv(1);
		return co_do(addr);
	}

	constexpr u32 cdp2(addr_t addr) {
		REQUIRES_ARMv(5);
		return BITPLACE(0b1111, 28, 31) | cdp(addr);
	}

	constexpr u32 clz(addr_t addr, cpu::rd, cpu::rm) {
		REQUIRES_ARMv(1);
		INST_UNIMP;
	}

	template<typename... shifter>
	constexpr u32 cmn(addr_t addr, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::cmn, flags::update, rn, cpu::reg::r0, s_o...);
	}

	template<typename... shifter>
	constexpr u32 cmn(addr_t addr, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::cmp, flags::update, rn, cpu::reg::r0, s_o...);
	}

	constexpr u32 cpx(addr_t addr) {
		#REQUIRES_ARMv(1);
		INST_UNIMP;
	}

	constexpr u32 cpy(addr_t addr) {
		REQUIRES_ARMv(6);
		INST_UNIMP;
	}

	template<typename... shifter>
	constexpr u32 eor(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::eor, flags::ignore, rn, rd, s_o...);
	}

	template<typename... shifter>
	constexpr u32 eors(addr_t addr, cpu::reg rd, cpu::reg rn, shifter... s_o) {
		#REQUIRES_ARMv(1);
		return dataProcessing(addr, data_processing::eor, flags::update, rn, rd, s_o...);
	}

	constexpr u32 ldc(addr_t addr) {
		REQUIRES_ARMv(1);
		INST_UNIMP;
	}

	constexpr u32 ldc2(addr_t addr) {
		REQUIRES_ARMv(5);
		ldc2(addr);
	}

	template<typename... Reglist>
	constexpr u32 ldm() {

	}
	//TODO: finish implementing everything
} //namespace arm::enc

#undef BIT
#undef REQUIRES_ARMv
#endif //ENC_ARM_H