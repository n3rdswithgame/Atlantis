#ifndef ARM_INS_H
#define ARM_INS_H

#include "cpu.h"

#include "common/bit/mask.h"

#include <variant>

#include <capstone/arm.h>

namespace arm {
	using bit::mask::bit_range;

	enum class isa {
		arm,
		thumb,
	};

	enum class cond : u32 {
		//taken straight form the ARM Archatecture Reference Manual

													  // meaning								flags
		eq = bit_range<0b0000, 31, 28>::m, // Equal 								Z set
		ne = bit_range<0b0001, 31, 28>::m, // Not equal 							Z clear
		cs = bit_range<0b0010, 31, 28>::m, // Carry set/unsigned higher or same 	C set
		cc = bit_range<0b0011, 31, 28>::m, // Carry clear/unsigned lower 			C clear
		mi = bit_range<0b0100, 31, 28>::m, // Minus/negative 						N set
		pl = bit_range<0b0101, 31, 28>::m, // Plus/positive or zero 				N clear
		vs = bit_range<0b0110, 31, 28>::m, // Overflow 								V set
		vc = bit_range<0b0111, 31, 28>::m, // No overflow 							V clear
		hi = bit_range<0b1000, 31, 28>::m, // Unsigned higher 						C set and Z clear
		ls = bit_range<0b1001, 31, 28>::m, // Unsigned lower or same 				C clear or Z set
		ge = bit_range<0b1010, 31, 28>::m, // Signed greater than or equal 			(N == V)
		lt = bit_range<0b1011, 31, 28>::m, // Signed less than 						(N != V)
		gt = bit_range<0b1100, 31, 28>::m, // Signed greater than 					(Z == 0,N == V)
		le = bit_range<0b1101, 31, 28>::m, // Signed less than or equal 			(Z == 1 or N != V)
		al = bit_range<0b1110, 31, 28>::m, // Always (unconditional) 				always

		// the invalid conditional is only used on instructions that can't be conditional,
		// so in the lifter those will just be tagged as AL

		hs = cs,
		lo = cc,
	};

	constexpr cond csCondToAtl(arm_cc cc) {
		switch(cc) {
			case ARM_CC_EQ:
				return cond::eq;
			case ARM_CC_NE:
				return cond::ne;
			case ARM_CC_HS:
				return cond::hs;
			case ARM_CC_LO:
				return cond::lo;
			case ARM_CC_MI:
				return cond::mi;
			case ARM_CC_PL:
				return cond::pl;
			case ARM_CC_VS:
				return cond::vs;
			case ARM_CC_VC:
				return cond::vc;
			case ARM_CC_HI:
				return cond::hi;
			case ARM_CC_LS:
				return cond::ls;
			case ARM_CC_GE:
				return cond::ge;
			case ARM_CC_LT:
				return cond::lt;
			case ARM_CC_GT:
				return cond::gt;
			case ARM_CC_LE:
				return cond::le;
			case ARM_CC_AL:
				return cond::al;

			case ARM_CC_INVALID: break;
		}
		return UNREACHABLE(cond);
	}

	enum class shift {
		lsl = bit_range<0b00, 6, 5>::m,
		lsr = bit_range<0b01, 6, 5>::m,
		asl = bit_range<0b10, 6, 5>::m,
		asr = bit_range<0b01, 6, 5>::m,
	};

	enum class operation {
		illformed,

		Adc,
		Add,
		Adr,
		Aesd,
		Aese,
		Aesimc,
		Aesmc,
		And,
		Bfc,
		Bfi,
		Bic,
		Bkpt,
		Bl,
		Blx,
		Bx,
		Bxj,
		B,
		Cdp,
		Cdp2,
		Clrex,
		Clz,
		Cmn,
		Cmp,
		Cps,
		Crc32b,
		Crc32cb,
		Crc32ch,
		Crc32cw,
		Crc32h,
		Crc32w,
		Dbg,
		Dmb,
		Dsb,
		Eor,
		Eret,
		Vmov,
		Fldmdbx,
		Fldmiax,
		Vmrs,
		Fstmdbx,
		Fstmiax,
		Hint,
		Hlt,
		Hvc,
		Isb,
		Lda,
		Ldab,
		Ldaex,
		Ldaexb,
		Ldaexd,
		Ldaexh,
		Ldah,
		Ldc2l,
		Ldc2,
		Ldcl,
		Ldc,
		Ldmda,
		Ldmdb,
		Ldm,
		Ldmib,
		Ldrbt,
		Ldrb,
		Ldrd,
		Ldrex,
		Ldrexb,
		Ldrexd,
		Ldrexh,
		Ldrh,
		Ldrht,
		Ldrsb,
		Ldrsbt,
		Ldrsh,
		Ldrsht,
		Ldrt,
		Ldr,
		Mcr,
		Mcr2,
		Mcrr,
		Mcrr2,
		Mla,
		Mls,
		Mov,
		Movt,
		Movw,
		Mrc,
		Mrc2,
		Mrrc,
		Mrrc2,
		Mrs,
		Msr,
		Mul,
		Mvn,
		Orr,
		Pkhbt,
		Pkhtb,
		Pldw,
		Pld,
		Pli,
		Qadd,
		Qadd16,
		Qadd8,
		Qasx,
		Qdadd,
		Qdsub,
		Qsax,
		Qsub,
		Qsub16,
		Qsub8,
		Rbit,
		Rev,
		Rev16,
		Revsh,
		Rfeda,
		Rfedb,
		Rfeia,
		Rfeib,
		Rsb,
		Rsc,
		Sadd16,
		Sadd8,
		Sasx,
		Sbc,
		Sbfx,
		Sdiv,
		Sel,
		Setend,
		Sha1c,
		Sha1h,
		Sha1m,
		Sha1p,
		Sha1su0,
		Sha1su1,
		Sha256h,
		Sha256h2,
		Sha256su0,
		Sha256su1,
		Shadd16,
		Shadd8,
		Shasx,
		Shsax,
		Shsub16,
		Shsub8,
		Smc,
		Smlabb,
		Smlabt,
		Smlad,
		Smladx,
		Smlal,
		Smlalbb,
		Smlalbt,
		Smlald,
		Smlaldx,
		Smlaltb,
		Smlaltt,
		Smlatb,
		Smlatt,
		Smlawb,
		Smlawt,
		Smlsd,
		Smlsdx,
		Smlsld,
		Smlsldx,
		Smmla,
		Smmlar,
		Smmls,
		Smmlsr,
		Smmul,
		Smmulr,
		Smuad,
		Smuadx,
		Smulbb,
		Smulbt,
		Smull,
		Smultb,
		Smultt,
		Smulwb,
		Smulwt,
		Smusd,
		Smusdx,
		Srsda,
		Srsdb,
		Srsia,
		Srsib,
		Ssat,
		Ssat16,
		Ssax,
		Ssub16,
		Ssub8,
		Stc2l,
		Stc2,
		Stcl,
		Stc,
		Stl,
		Stlb,
		Stlex,
		Stlexb,
		Stlexd,
		Stlexh,
		Stlh,
		Stmda,
		Stmdb,
		Stm,
		Stmib,
		Strbt,
		Strb,
		Strd,
		Strex,
		Strexb,
		Strexd,
		Strexh,
		Strh,
		Strht,
		Strt,
		Str,
		Sub,
		Svc,
		Swp,
		Swpb,
		Sxtab,
		Sxtab16,
		Sxtah,
		Sxtb,
		Sxtb16,
		Sxth,
		Teq,
		Trap,
		Tst,
		Uadd16,
		Uadd8,
		Uasx,
		Ubfx,
		Udf,
		Udiv,
		Uhadd16,
		Uhadd8,
		Uhasx,
		Uhsax,
		Uhsub16,
		Uhsub8,
		Umaal,
		Umlal,
		Umull,
		Uqadd16,
		Uqadd8,
		Uqasx,
		Uqsax,
		Uqsub16,
		Uqsub8,
		Usad8,
		Usada8,
		Usat,
		Usat16,
		Usax,
		Usub16,
		Usub8,
		Uxtab,
		Uxtab16,
		Uxtah,
		Uxtb,
		Uxtb16,
		Uxth,
		Vabal,
		Vaba,
		Vabdl,
		Vabd,
		Vabs,
		Vacge,
		Vacgt,
		Vadd,
		Vaddhn,
		Vaddl,
		Vaddw,
		Vand,
		Vbic,
		Vbif,
		Vbit,
		Vbsl,
		Vceq,
		Vcge,
		Vcgt,
		Vcle,
		Vcls,
		Vclt,
		Vclz,
		Vcmp,
		Vcmpe,
		Vcnt,
		Vcvta,
		Vcvtb,
		Vcvt,
		Vcvtm,
		Vcvtn,
		Vcvtp,
		Vcvtt,
		Vdiv,
		Vdup,
		Veor,
		Vext,
		Vfma,
		Vfms,
		Vfnma,
		Vfnms,
		Vhadd,
		Vhsub,
		Vld1,
		Vld2,
		Vld3,
		Vld4,
		Vldmdb,
		Vldmia,
		Vldr,
		Vmaxnm,
		Vmax,
		Vminnm,
		Vmin,
		Vmla,
		Vmlal,
		Vmls,
		Vmlsl,
		Vmovl,
		Vmovn,
		Vmsr,
		Vmul,
		Vmull,
		Vmvn,
		Vneg,
		Vnmla,
		Vnmls,
		Vnmul,
		Vorn,
		Vorr,
		Vpadal,
		Vpaddl,
		Vpadd,
		Vpmax,
		Vpmin,
		Vqabs,
		Vqadd,
		Vqdmlal,
		Vqdmlsl,
		Vqdmulh,
		Vqdmull,
		Vqmovun,
		Vqmovn,
		Vqneg,
		Vqrdmulh,
		Vqrshl,
		Vqrshrn,
		Vqrshrun,
		Vqshl,
		Vqshlu,
		Vqshrn,
		Vqshrun,
		Vqsub,
		Vraddhn,
		Vrecpe,
		Vrecps,
		Vrev16,
		Vrev32,
		Vrev64,
		Vrhadd,
		Vrinta,
		Vrintm,
		Vrintn,
		Vrintp,
		Vrintr,
		Vrintx,
		Vrintz,
		Vrshl,
		Vrshrn,
		Vrshr,
		Vrsqrte,
		Vrsqrts,
		Vrsra,
		Vrsubhn,
		Vseleq,
		Vselge,
		Vselgt,
		Vselvs,
		Vshll,
		Vshl,
		Vshrn,
		Vshr,
		Vsli,
		Vsqrt,
		Vsra,
		Vsri,
		Vst1,
		Vst2,
		Vst3,
		Vst4,
		Vstmdb,
		Vstmia,
		Vstr,
		Vsub,
		Vsubhn,
		Vsubl,
		Vsubw,
		Vswp,
		Vtbl,
		Vtbx,
		Vcvtr,
		Vtrn,
		Vtst,
		Vuzp,
		Vzip,
		Addw,
		Asr,
		Dcps1,
		Dcps2,
		Dcps3,
		It,
		Lsl,
		Lsr,
		Orn,
		Ror,
		Rrx,
		Subw,
		Tbb,
		Tbh,
		Cbnz,
		Cbz,
		Pop,
		Push,

		// special instructions
		Nop,
		Yield,
		Wfe,
		Wfi,
		Sev,
		Sevl,
		Vpush,
		Vpop,

		count,
	};

	constexpr operation csOpToAtl (unsigned int capstone_insn) {
		switch(capstone_insn) {
			case ARM_INS_INVALID:
				return operation::illformed;
			case ARM_INS_ADC:
				return operation::Adc;
			case ARM_INS_ADD:
				return operation::Add;
			case ARM_INS_ADR:
				return operation::Adr;
			case ARM_INS_AESD:
				return operation::Aesd;
			case ARM_INS_AESE:
				return operation::Aese;
			case ARM_INS_AESIMC:
				return operation::Aesimc;
			case ARM_INS_AESMC:
				return operation::Aesmc;
			case ARM_INS_AND:
				return operation::And;
			case ARM_INS_BFC:
				return operation::Bfc;
			case ARM_INS_BFI:
				return operation::Bfi;
			case ARM_INS_BIC:
				return operation::Bic;
			case ARM_INS_BKPT:
				return operation::Bkpt;
			case ARM_INS_BL:
				return operation::Bl;
			case ARM_INS_BLX:
				return operation::Blx;
			case ARM_INS_BX:
				return operation::Bx;
			case ARM_INS_BXJ:
				return operation::Bxj;
			case ARM_INS_B:
				return operation::B;
			case ARM_INS_CDP:
				return operation::Cdp;
			case ARM_INS_CDP2:
				return operation::Cdp2;
			case ARM_INS_CLREX:
				return operation::Clrex;
			case ARM_INS_CLZ:
				return operation::Clz;
			case ARM_INS_CMN:
				return operation::Cmn;
			case ARM_INS_CMP:
				return operation::Cmp;
			case ARM_INS_CPS:
				return operation::Cps;
			case ARM_INS_CRC32B:
				return operation::Crc32b;
			case ARM_INS_CRC32CB:
				return operation::Crc32cb;
			case ARM_INS_CRC32CH:
				return operation::Crc32ch;
			case ARM_INS_CRC32CW:
				return operation::Crc32cw;
			case ARM_INS_CRC32H:
				return operation::Crc32h;
			case ARM_INS_CRC32W:
				return operation::Crc32w;
			case ARM_INS_DBG:
				return operation::Dbg;
			case ARM_INS_DMB:
				return operation::Dmb;
			case ARM_INS_DSB:
				return operation::Dsb;
			case ARM_INS_EOR:
				return operation::Eor;
			case ARM_INS_ERET:
				return operation::Eret;
			case ARM_INS_VMOV:
				return operation::Vmov;
			case ARM_INS_FLDMDBX:
				return operation::Fldmdbx;
			case ARM_INS_FLDMIAX:
				return operation::Fldmiax;
			case ARM_INS_VMRS:
				return operation::Vmrs;
			case ARM_INS_FSTMDBX:
				return operation::Fstmdbx;
			case ARM_INS_FSTMIAX:
				return operation::Fstmiax;
			case ARM_INS_HINT:
				return operation::Hint;
			case ARM_INS_HLT:
				return operation::Hlt;
			case ARM_INS_HVC:
				return operation::Hvc;
			case ARM_INS_ISB:
				return operation::Isb;
			case ARM_INS_LDA:
				return operation::Lda;
			case ARM_INS_LDAB:
				return operation::Ldab;
			case ARM_INS_LDAEX:
				return operation::Ldaex;
			case ARM_INS_LDAEXB:
				return operation::Ldaexb;
			case ARM_INS_LDAEXD:
				return operation::Ldaexd;
			case ARM_INS_LDAEXH:
				return operation::Ldaexh;
			case ARM_INS_LDAH:
				return operation::Ldah;
			case ARM_INS_LDC2L:
				return operation::Ldc2l;
			case ARM_INS_LDC2:
				return operation::Ldc2;
			case ARM_INS_LDCL:
				return operation::Ldcl;
			case ARM_INS_LDC:
				return operation::Ldc;
			case ARM_INS_LDMDA:
				return operation::Ldmda;
			case ARM_INS_LDMDB:
				return operation::Ldmdb;
			case ARM_INS_LDM:
				return operation::Ldm;
			case ARM_INS_LDMIB:
				return operation::Ldmib;
			case ARM_INS_LDRBT:
				return operation::Ldrbt;
			case ARM_INS_LDRB:
				return operation::Ldrb;
			case ARM_INS_LDRD:
				return operation::Ldrd;
			case ARM_INS_LDREX:
				return operation::Ldrex;
			case ARM_INS_LDREXB:
				return operation::Ldrexb;
			case ARM_INS_LDREXD:
				return operation::Ldrexd;
			case ARM_INS_LDREXH:
				return operation::Ldrexh;
			case ARM_INS_LDRH:
				return operation::Ldrh;
			case ARM_INS_LDRHT:
				return operation::Ldrht;
			case ARM_INS_LDRSB:
				return operation::Ldrsb;
			case ARM_INS_LDRSBT:
				return operation::Ldrsbt;
			case ARM_INS_LDRSH:
				return operation::Ldrsh;
			case ARM_INS_LDRSHT:
				return operation::Ldrsht;
			case ARM_INS_LDRT:
				return operation::Ldrt;
			case ARM_INS_LDR:
				return operation::Ldr;
			case ARM_INS_MCR:
				return operation::Mcr;
			case ARM_INS_MCR2:
				return operation::Mcr2;
			case ARM_INS_MCRR:
				return operation::Mcrr;
			case ARM_INS_MCRR2:
				return operation::Mcrr2;
			case ARM_INS_MLA:
				return operation::Mla;
			case ARM_INS_MLS:
				return operation::Mls;
			case ARM_INS_MOV:
				return operation::Mov;
			case ARM_INS_MOVT:
				return operation::Movt;
			case ARM_INS_MOVW:
				return operation::Movw;
			case ARM_INS_MRC:
				return operation::Mrc;
			case ARM_INS_MRC2:
				return operation::Mrc2;
			case ARM_INS_MRRC:
				return operation::Mrrc;
			case ARM_INS_MRRC2:
				return operation::Mrrc2;
			case ARM_INS_MRS:
				return operation::Mrs;
			case ARM_INS_MSR:
				return operation::Msr;
			case ARM_INS_MUL:
				return operation::Mul;
			case ARM_INS_MVN:
				return operation::Mvn;
			case ARM_INS_ORR:
				return operation::Orr;
			case ARM_INS_PKHBT:
				return operation::Pkhbt;
			case ARM_INS_PKHTB:
				return operation::Pkhtb;
			case ARM_INS_PLDW:
				return operation::Pldw;
			case ARM_INS_PLD:
				return operation::Pld;
			case ARM_INS_PLI:
				return operation::Pli;
			case ARM_INS_QADD:
				return operation::Qadd;
			case ARM_INS_QADD16:
				return operation::Qadd16;
			case ARM_INS_QADD8:
				return operation::Qadd8;
			case ARM_INS_QASX:
				return operation::Qasx;
			case ARM_INS_QDADD:
				return operation::Qdadd;
			case ARM_INS_QDSUB:
				return operation::Qdsub;
			case ARM_INS_QSAX:
				return operation::Qsax;
			case ARM_INS_QSUB:
				return operation::Qsub;
			case ARM_INS_QSUB16:
				return operation::Qsub16;
			case ARM_INS_QSUB8:
				return operation::Qsub8;
			case ARM_INS_RBIT:
				return operation::Rbit;
			case ARM_INS_REV:
				return operation::Rev;
			case ARM_INS_REV16:
				return operation::Rev16;
			case ARM_INS_REVSH:
				return operation::Revsh;
			case ARM_INS_RFEDA:
				return operation::Rfeda;
			case ARM_INS_RFEDB:
				return operation::Rfedb;
			case ARM_INS_RFEIA:
				return operation::Rfeia;
			case ARM_INS_RFEIB:
				return operation::Rfeib;
			case ARM_INS_RSB:
				return operation::Rsb;
			case ARM_INS_RSC:
				return operation::Rsc;
			case ARM_INS_SADD16:
				return operation::Sadd16;
			case ARM_INS_SADD8:
				return operation::Sadd8;
			case ARM_INS_SASX:
				return operation::Sasx;
			case ARM_INS_SBC:
				return operation::Sbc;
			case ARM_INS_SBFX:
				return operation::Sbfx;
			case ARM_INS_SDIV:
				return operation::Sdiv;
			case ARM_INS_SEL:
				return operation::Sel;
			case ARM_INS_SETEND:
				return operation::Setend;
			case ARM_INS_SHA1C:
				return operation::Sha1c;
			case ARM_INS_SHA1H:
				return operation::Sha1h;
			case ARM_INS_SHA1M:
				return operation::Sha1m;
			case ARM_INS_SHA1P:
				return operation::Sha1p;
			case ARM_INS_SHA1SU0:
				return operation::Sha1su0;
			case ARM_INS_SHA1SU1:
				return operation::Sha1su1;
			case ARM_INS_SHA256H:
				return operation::Sha256h;
			case ARM_INS_SHA256H2:
				return operation::Sha256h2;
			case ARM_INS_SHA256SU0:
				return operation::Sha256su0;
			case ARM_INS_SHA256SU1:
				return operation::Sha256su1;
			case ARM_INS_SHADD16:
				return operation::Shadd16;
			case ARM_INS_SHADD8:
				return operation::Shadd8;
			case ARM_INS_SHASX:
				return operation::Shasx;
			case ARM_INS_SHSAX:
				return operation::Shsax;
			case ARM_INS_SHSUB16:
				return operation::Shsub16;
			case ARM_INS_SHSUB8:
				return operation::Shsub8;
			case ARM_INS_SMC:
				return operation::Smc;
			case ARM_INS_SMLABB:
				return operation::Smlabb;
			case ARM_INS_SMLABT:
				return operation::Smlabt;
			case ARM_INS_SMLAD:
				return operation::Smlad;
			case ARM_INS_SMLADX:
				return operation::Smladx;
			case ARM_INS_SMLAL:
				return operation::Smlal;
			case ARM_INS_SMLALBB:
				return operation::Smlalbb;
			case ARM_INS_SMLALBT:
				return operation::Smlalbt;
			case ARM_INS_SMLALD:
				return operation::Smlald;
			case ARM_INS_SMLALDX:
				return operation::Smlaldx;
			case ARM_INS_SMLALTB:
				return operation::Smlaltb;
			case ARM_INS_SMLALTT:
				return operation::Smlaltt;
			case ARM_INS_SMLATB:
				return operation::Smlatb;
			case ARM_INS_SMLATT:
				return operation::Smlatt;
			case ARM_INS_SMLAWB:
				return operation::Smlawb;
			case ARM_INS_SMLAWT:
				return operation::Smlawt;
			case ARM_INS_SMLSD:
				return operation::Smlsd;
			case ARM_INS_SMLSDX:
				return operation::Smlsdx;
			case ARM_INS_SMLSLD:
				return operation::Smlsld;
			case ARM_INS_SMLSLDX:
				return operation::Smlsldx;
			case ARM_INS_SMMLA:
				return operation::Smmla;
			case ARM_INS_SMMLAR:
				return operation::Smmlar;
			case ARM_INS_SMMLS:
				return operation::Smmls;
			case ARM_INS_SMMLSR:
				return operation::Smmlsr;
			case ARM_INS_SMMUL:
				return operation::Smmul;
			case ARM_INS_SMMULR:
				return operation::Smmulr;
			case ARM_INS_SMUAD:
				return operation::Smuad;
			case ARM_INS_SMUADX:
				return operation::Smuadx;
			case ARM_INS_SMULBB:
				return operation::Smulbb;
			case ARM_INS_SMULBT:
				return operation::Smulbt;
			case ARM_INS_SMULL:
				return operation::Smull;
			case ARM_INS_SMULTB:
				return operation::Smultb;
			case ARM_INS_SMULTT:
				return operation::Smultt;
			case ARM_INS_SMULWB:
				return operation::Smulwb;
			case ARM_INS_SMULWT:
				return operation::Smulwt;
			case ARM_INS_SMUSD:
				return operation::Smusd;
			case ARM_INS_SMUSDX:
				return operation::Smusdx;
			case ARM_INS_SRSDA:
				return operation::Srsda;
			case ARM_INS_SRSDB:
				return operation::Srsdb;
			case ARM_INS_SRSIA:
				return operation::Srsia;
			case ARM_INS_SRSIB:
				return operation::Srsib;
			case ARM_INS_SSAT:
				return operation::Ssat;
			case ARM_INS_SSAT16:
				return operation::Ssat16;
			case ARM_INS_SSAX:
				return operation::Ssax;
			case ARM_INS_SSUB16:
				return operation::Ssub16;
			case ARM_INS_SSUB8:
				return operation::Ssub8;
			case ARM_INS_STC2L:
				return operation::Stc2l;
			case ARM_INS_STC2:
				return operation::Stc2;
			case ARM_INS_STCL:
				return operation::Stcl;
			case ARM_INS_STC:
				return operation::Stc;
			case ARM_INS_STL:
				return operation::Stl;
			case ARM_INS_STLB:
				return operation::Stlb;
			case ARM_INS_STLEX:
				return operation::Stlex;
			case ARM_INS_STLEXB:
				return operation::Stlexb;
			case ARM_INS_STLEXD:
				return operation::Stlexd;
			case ARM_INS_STLEXH:
				return operation::Stlexh;
			case ARM_INS_STLH:
				return operation::Stlh;
			case ARM_INS_STMDA:
				return operation::Stmda;
			case ARM_INS_STMDB:
				return operation::Stmdb;
			case ARM_INS_STM:
				return operation::Stm;
			case ARM_INS_STMIB:
				return operation::Stmib;
			case ARM_INS_STRBT:
				return operation::Strbt;
			case ARM_INS_STRB:
				return operation::Strb;
			case ARM_INS_STRD:
				return operation::Strd;
			case ARM_INS_STREX:
				return operation::Strex;
			case ARM_INS_STREXB:
				return operation::Strexb;
			case ARM_INS_STREXD:
				return operation::Strexd;
			case ARM_INS_STREXH:
				return operation::Strexh;
			case ARM_INS_STRH:
				return operation::Strh;
			case ARM_INS_STRHT:
				return operation::Strht;
			case ARM_INS_STRT:
				return operation::Strt;
			case ARM_INS_STR:
				return operation::Str;
			case ARM_INS_SUB:
				return operation::Sub;
			case ARM_INS_SVC:
				return operation::Svc;
			case ARM_INS_SWP:
				return operation::Swp;
			case ARM_INS_SWPB:
				return operation::Swpb;
			case ARM_INS_SXTAB:
				return operation::Sxtab;
			case ARM_INS_SXTAB16:
				return operation::Sxtab16;
			case ARM_INS_SXTAH:
				return operation::Sxtah;
			case ARM_INS_SXTB:
				return operation::Sxtb;
			case ARM_INS_SXTB16:
				return operation::Sxtb16;
			case ARM_INS_SXTH:
				return operation::Sxth;
			case ARM_INS_TEQ:
				return operation::Teq;
			case ARM_INS_TRAP:
				return operation::Trap;
			case ARM_INS_TST:
				return operation::Tst;
			case ARM_INS_UADD16:
				return operation::Uadd16;
			case ARM_INS_UADD8:
				return operation::Uadd8;
			case ARM_INS_UASX:
				return operation::Uasx;
			case ARM_INS_UBFX:
				return operation::Ubfx;
			case ARM_INS_UDF:
				return operation::Udf;
			case ARM_INS_UDIV:
				return operation::Udiv;
			case ARM_INS_UHADD16:
				return operation::Uhadd16;
			case ARM_INS_UHADD8:
				return operation::Uhadd8;
			case ARM_INS_UHASX:
				return operation::Uhasx;
			case ARM_INS_UHSAX:
				return operation::Uhsax;
			case ARM_INS_UHSUB16:
				return operation::Uhsub16;
			case ARM_INS_UHSUB8:
				return operation::Uhsub8;
			case ARM_INS_UMAAL:
				return operation::Umaal;
			case ARM_INS_UMLAL:
				return operation::Umlal;
			case ARM_INS_UMULL:
				return operation::Umull;
			case ARM_INS_UQADD16:
				return operation::Uqadd16;
			case ARM_INS_UQADD8:
				return operation::Uqadd8;
			case ARM_INS_UQASX:
				return operation::Uqasx;
			case ARM_INS_UQSAX:
				return operation::Uqsax;
			case ARM_INS_UQSUB16:
				return operation::Uqsub16;
			case ARM_INS_UQSUB8:
				return operation::Uqsub8;
			case ARM_INS_USAD8:
				return operation::Usad8;
			case ARM_INS_USADA8:
				return operation::Usada8;
			case ARM_INS_USAT:
				return operation::Usat;
			case ARM_INS_USAT16:
				return operation::Usat16;
			case ARM_INS_USAX:
				return operation::Usax;
			case ARM_INS_USUB16:
				return operation::Usub16;
			case ARM_INS_USUB8:
				return operation::Usub8;
			case ARM_INS_UXTAB:
				return operation::Uxtab;
			case ARM_INS_UXTAB16:
				return operation::Uxtab16;
			case ARM_INS_UXTAH:
				return operation::Uxtah;
			case ARM_INS_UXTB:
				return operation::Uxtb;
			case ARM_INS_UXTB16:
				return operation::Uxtb16;
			case ARM_INS_UXTH:
				return operation::Uxth;
			case ARM_INS_VABAL:
				return operation::Vabal;
			case ARM_INS_VABA:
				return operation::Vaba;
			case ARM_INS_VABDL:
				return operation::Vabdl;
			case ARM_INS_VABD:
				return operation::Vabd;
			case ARM_INS_VABS:
				return operation::Vabs;
			case ARM_INS_VACGE:
				return operation::Vacge;
			case ARM_INS_VACGT:
				return operation::Vacgt;
			case ARM_INS_VADD:
				return operation::Vadd;
			case ARM_INS_VADDHN:
				return operation::Vaddhn;
			case ARM_INS_VADDL:
				return operation::Vaddl;
			case ARM_INS_VADDW:
				return operation::Vaddw;
			case ARM_INS_VAND:
				return operation::Vand;
			case ARM_INS_VBIC:
				return operation::Vbic;
			case ARM_INS_VBIF:
				return operation::Vbif;
			case ARM_INS_VBIT:
				return operation::Vbit;
			case ARM_INS_VBSL:
				return operation::Vbsl;
			case ARM_INS_VCEQ:
				return operation::Vceq;
			case ARM_INS_VCGE:
				return operation::Vcge;
			case ARM_INS_VCGT:
				return operation::Vcgt;
			case ARM_INS_VCLE:
				return operation::Vcle;
			case ARM_INS_VCLS:
				return operation::Vcls;
			case ARM_INS_VCLT:
				return operation::Vclt;
			case ARM_INS_VCLZ:
				return operation::Vclz;
			case ARM_INS_VCMP:
				return operation::Vcmp;
			case ARM_INS_VCMPE:
				return operation::Vcmpe;
			case ARM_INS_VCNT:
				return operation::Vcnt;
			case ARM_INS_VCVTA:
				return operation::Vcvta;
			case ARM_INS_VCVTB:
				return operation::Vcvtb;
			case ARM_INS_VCVT:
				return operation::Vcvt;
			case ARM_INS_VCVTM:
				return operation::Vcvtm;
			case ARM_INS_VCVTN:
				return operation::Vcvtn;
			case ARM_INS_VCVTP:
				return operation::Vcvtp;
			case ARM_INS_VCVTT:
				return operation::Vcvtt;
			case ARM_INS_VDIV:
				return operation::Vdiv;
			case ARM_INS_VDUP:
				return operation::Vdup;
			case ARM_INS_VEOR:
				return operation::Veor;
			case ARM_INS_VEXT:
				return operation::Vext;
			case ARM_INS_VFMA:
				return operation::Vfma;
			case ARM_INS_VFMS:
				return operation::Vfms;
			case ARM_INS_VFNMA:
				return operation::Vfnma;
			case ARM_INS_VFNMS:
				return operation::Vfnms;
			case ARM_INS_VHADD:
				return operation::Vhadd;
			case ARM_INS_VHSUB:
				return operation::Vhsub;
			case ARM_INS_VLD1:
				return operation::Vld1;
			case ARM_INS_VLD2:
				return operation::Vld2;
			case ARM_INS_VLD3:
				return operation::Vld3;
			case ARM_INS_VLD4:
				return operation::Vld4;
			case ARM_INS_VLDMDB:
				return operation::Vldmdb;
			case ARM_INS_VLDMIA:
				return operation::Vldmia;
			case ARM_INS_VLDR:
				return operation::Vldr;
			case ARM_INS_VMAXNM:
				return operation::Vmaxnm;
			case ARM_INS_VMAX:
				return operation::Vmax;
			case ARM_INS_VMINNM:
				return operation::Vminnm;
			case ARM_INS_VMIN:
				return operation::Vmin;
			case ARM_INS_VMLA:
				return operation::Vmla;
			case ARM_INS_VMLAL:
				return operation::Vmlal;
			case ARM_INS_VMLS:
				return operation::Vmls;
			case ARM_INS_VMLSL:
				return operation::Vmlsl;
			case ARM_INS_VMOVL:
				return operation::Vmovl;
			case ARM_INS_VMOVN:
				return operation::Vmovn;
			case ARM_INS_VMSR:
				return operation::Vmsr;
			case ARM_INS_VMUL:
				return operation::Vmul;
			case ARM_INS_VMULL:
				return operation::Vmull;
			case ARM_INS_VMVN:
				return operation::Vmvn;
			case ARM_INS_VNEG:
				return operation::Vneg;
			case ARM_INS_VNMLA:
				return operation::Vnmla;
			case ARM_INS_VNMLS:
				return operation::Vnmls;
			case ARM_INS_VNMUL:
				return operation::Vnmul;
			case ARM_INS_VORN:
				return operation::Vorn;
			case ARM_INS_VORR:
				return operation::Vorr;
			case ARM_INS_VPADAL:
				return operation::Vpadal;
			case ARM_INS_VPADDL:
				return operation::Vpaddl;
			case ARM_INS_VPADD:
				return operation::Vpadd;
			case ARM_INS_VPMAX:
				return operation::Vpmax;
			case ARM_INS_VPMIN:
				return operation::Vpmin;
			case ARM_INS_VQABS:
				return operation::Vqabs;
			case ARM_INS_VQADD:
				return operation::Vqadd;
			case ARM_INS_VQDMLAL:
				return operation::Vqdmlal;
			case ARM_INS_VQDMLSL:
				return operation::Vqdmlsl;
			case ARM_INS_VQDMULH:
				return operation::Vqdmulh;
			case ARM_INS_VQDMULL:
				return operation::Vqdmull;
			case ARM_INS_VQMOVUN:
				return operation::Vqmovun;
			case ARM_INS_VQMOVN:
				return operation::Vqmovn;
			case ARM_INS_VQNEG:
				return operation::Vqneg;
			case ARM_INS_VQRDMULH:
				return operation::Vqrdmulh;
			case ARM_INS_VQRSHL:
				return operation::Vqrshl;
			case ARM_INS_VQRSHRN:
				return operation::Vqrshrn;
			case ARM_INS_VQRSHRUN:
				return operation::Vqrshrun;
			case ARM_INS_VQSHL:
				return operation::Vqshl;
			case ARM_INS_VQSHLU:
				return operation::Vqshlu;
			case ARM_INS_VQSHRN:
				return operation::Vqshrn;
			case ARM_INS_VQSHRUN:
				return operation::Vqshrun;
			case ARM_INS_VQSUB:
				return operation::Vqsub;
			case ARM_INS_VRADDHN:
				return operation::Vraddhn;
			case ARM_INS_VRECPE:
				return operation::Vrecpe;
			case ARM_INS_VRECPS:
				return operation::Vrecps;
			case ARM_INS_VREV16:
				return operation::Vrev16;
			case ARM_INS_VREV32:
				return operation::Vrev32;
			case ARM_INS_VREV64:
				return operation::Vrev64;
			case ARM_INS_VRHADD:
				return operation::Vrhadd;
			case ARM_INS_VRINTA:
				return operation::Vrinta;
			case ARM_INS_VRINTM:
				return operation::Vrintm;
			case ARM_INS_VRINTN:
				return operation::Vrintn;
			case ARM_INS_VRINTP:
				return operation::Vrintp;
			case ARM_INS_VRINTR:
				return operation::Vrintr;
			case ARM_INS_VRINTX:
				return operation::Vrintx;
			case ARM_INS_VRINTZ:
				return operation::Vrintz;
			case ARM_INS_VRSHL:
				return operation::Vrshl;
			case ARM_INS_VRSHRN:
				return operation::Vrshrn;
			case ARM_INS_VRSHR:
				return operation::Vrshr;
			case ARM_INS_VRSQRTE:
				return operation::Vrsqrte;
			case ARM_INS_VRSQRTS:
				return operation::Vrsqrts;
			case ARM_INS_VRSRA:
				return operation::Vrsra;
			case ARM_INS_VRSUBHN:
				return operation::Vrsubhn;
			case ARM_INS_VSELEQ:
				return operation::Vseleq;
			case ARM_INS_VSELGE:
				return operation::Vselge;
			case ARM_INS_VSELGT:
				return operation::Vselgt;
			case ARM_INS_VSELVS:
				return operation::Vselvs;
			case ARM_INS_VSHLL:
				return operation::Vshll;
			case ARM_INS_VSHL:
				return operation::Vshl;
			case ARM_INS_VSHRN:
				return operation::Vshrn;
			case ARM_INS_VSHR:
				return operation::Vshr;
			case ARM_INS_VSLI:
				return operation::Vsli;
			case ARM_INS_VSQRT:
				return operation::Vsqrt;
			case ARM_INS_VSRA:
				return operation::Vsra;
			case ARM_INS_VSRI:
				return operation::Vsri;
			case ARM_INS_VST1:
				return operation::Vst1;
			case ARM_INS_VST2:
				return operation::Vst2;
			case ARM_INS_VST3:
				return operation::Vst3;
			case ARM_INS_VST4:
				return operation::Vst4;
			case ARM_INS_VSTMDB:
				return operation::Vstmdb;
			case ARM_INS_VSTMIA:
				return operation::Vstmia;
			case ARM_INS_VSTR:
				return operation::Vstr;
			case ARM_INS_VSUB:
				return operation::Vsub;
			case ARM_INS_VSUBHN:
				return operation::Vsubhn;
			case ARM_INS_VSUBL:
				return operation::Vsubl;
			case ARM_INS_VSUBW:
				return operation::Vsubw;
			case ARM_INS_VSWP:
				return operation::Vswp;
			case ARM_INS_VTBL:
				return operation::Vtbl;
			case ARM_INS_VTBX:
				return operation::Vtbx;
			case ARM_INS_VCVTR:
				return operation::Vcvtr;
			case ARM_INS_VTRN:
				return operation::Vtrn;
			case ARM_INS_VTST:
				return operation::Vtst;
			case ARM_INS_VUZP:
				return operation::Vuzp;
			case ARM_INS_VZIP:
				return operation::Vzip;
			case ARM_INS_ADDW:
				return operation::Addw;
			case ARM_INS_ASR:
				return operation::Asr;
			case ARM_INS_DCPS1:
				return operation::Dcps1;
			case ARM_INS_DCPS2:
				return operation::Dcps2;
			case ARM_INS_DCPS3:
				return operation::Dcps3;
			case ARM_INS_IT:
				return operation::It;
			case ARM_INS_LSL:
				return operation::Lsl;
			case ARM_INS_LSR:
				return operation::Lsr;
			case ARM_INS_ORN:
				return operation::Orn;
			case ARM_INS_ROR:
				return operation::Ror;
			case ARM_INS_RRX:
				return operation::Rrx;
			case ARM_INS_SUBW:
				return operation::Subw;
			case ARM_INS_TBB:
				return operation::Tbb;
			case ARM_INS_TBH:
				return operation::Tbh;
			case ARM_INS_CBNZ:
				return operation::Cbnz;
			case ARM_INS_CBZ:
				return operation::Cbz;
			case ARM_INS_POP:
				return operation::Pop;
			case ARM_INS_PUSH:
				return operation::Push;

			case ARM_INS_NOP:
				return operation::Nop;
			case ARM_INS_YIELD:
				return operation::Yield;
			case ARM_INS_WFE:
				return operation::Wfe;
			case ARM_INS_WFI:
				return operation::Wfi;
			case ARM_INS_SEV:
				return operation::Sev;
			case ARM_INS_SEVL:
				return operation::Sevl;
			case ARM_INS_VPUSH:
				return operation::Vpush;
			case ARM_INS_VPOP:
				return operation::Vpop;

			case ARM_INS_ENDING:
				return operation::count;
		}
		return UNREACHABLE(operation);
	}
	
	namespace operand{
		enum class op_type : u8 {
			empty,
			gpr,
			user_gpr,
			mem,
			vpr_s,
			vpr_d,
			vpr_q,
			psr,
			imm,
			pimm,
			cimm,
			addr,
			reglist
		};
		enum class modifier_type : u8 {
			empty,
			asr_imm,
			lsl_imm,
			lsr_imm,
			ror_imm,
			rrx_imm,
			asr_reg,
			lsl_reg,
			lsr_reg,
			ror_reg,
			rrx_reg,
			offset,
			index,
			index_asr,
			index_lsl,
			index_lsr,
			index_ror,
			index_rrx,
		};



		struct box_val {
			bool negate = false;
			op_type type = op_type::empty;
			modifier_type mod = modifier_type::empty;
			s32 val = 0;
			s32 mod1 = 0;
			s32 mod2 = 0;
		};

		using operand_t = std::vector<box_val>;
	} //namespace arm::operand

	struct ins_t {
		addr_t 					addr = 0;
		u32						raw = 0;
		arm::cond				cond = cond::eq; //start with eq for 0 init with 0s
		operation	 			op = operation::illformed;
		operand::operand_t		operands{};


	};


	//This probably the first time I have seen variable templates be useful
	template<isa i>
	constexpr addr_t fetch_size = 0;

	template<>
	constexpr addr_t fetch_size<isa::arm> = 4;

	template<>
	constexpr addr_t fetch_size<isa::thumb> = 2;


	
} //namespace arm

template<>
struct fmt::formatter<arm::isa> {
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
	}		
};

template<>
struct fmt::formatter<arm::cond> {
	template <typename ParseContext>
	constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

	template <typename FormatContext>
	auto format(const arm::cond &cond, FormatContext &ctx) {
		#define toStr(x) case arm::cond::x : return format_to(ctx.out(), "cond::" #x)
		switch(cond) {
			toStr(eq);
			toStr(ne);
			toStr(cs);
			toStr(cc);
			toStr(mi);
			toStr(pl);
			toStr(vs);
			toStr(vc);
			toStr(hi);
			toStr(ls);
			toStr(ge);
			toStr(lt);
			toStr(gt);
			toStr(le);
			toStr(al);
		}
		return UNREACHABLE(decltype(format_to(ctx.out(), "")));
		#undef toStr
	}		
};

template<>
struct fmt::formatter<arm::operation> {
	template <typename ParseContext>
	constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

	template <typename FormatContext>
	auto format(const arm::operation op, FormatContext &ctx) {
		#define toStr(x) case arm::operation::x: return #x;
		auto opDispatch = [op]() -> const char *{
			switch(op){
				toStr(illformed);
				toStr(Adc);
				toStr(Add);
				toStr(Adr);
				toStr(Aesd);
				toStr(Aese);
				toStr(Aesimc);
				toStr(Aesmc);
				toStr(And);
				toStr(Bfc);
				toStr(Bfi);
				toStr(Bic);
				toStr(Bkpt);
				toStr(Bl);
				toStr(Blx);
				toStr(Bx);
				toStr(Bxj);
				toStr(B);
				toStr(Cdp);
				toStr(Cdp2);
				toStr(Clrex);
				toStr(Clz);
				toStr(Cmn);
				toStr(Cmp);
				toStr(Cps);
				toStr(Crc32b);
				toStr(Crc32cb);
				toStr(Crc32ch);
				toStr(Crc32cw);
				toStr(Crc32h);
				toStr(Crc32w);
				toStr(Dbg);
				toStr(Dmb);
				toStr(Dsb);
				toStr(Eor);
				toStr(Eret);
				toStr(Vmov);
				toStr(Fldmdbx);
				toStr(Fldmiax);
				toStr(Vmrs);
				toStr(Fstmdbx);
				toStr(Fstmiax);
				toStr(Hint);
				toStr(Hlt);
				toStr(Hvc);
				toStr(Isb);
				toStr(Lda);
				toStr(Ldab);
				toStr(Ldaex);
				toStr(Ldaexb);
				toStr(Ldaexd);
				toStr(Ldaexh);
				toStr(Ldah);
				toStr(Ldc2l);
				toStr(Ldc2);
				toStr(Ldcl);
				toStr(Ldc);
				toStr(Ldmda);
				toStr(Ldmdb);
				toStr(Ldm);
				toStr(Ldmib);
				toStr(Ldrbt);
				toStr(Ldrb);
				toStr(Ldrd);
				toStr(Ldrex);
				toStr(Ldrexb);
				toStr(Ldrexd);
				toStr(Ldrexh);
				toStr(Ldrh);
				toStr(Ldrht);
				toStr(Ldrsb);
				toStr(Ldrsbt);
				toStr(Ldrsh);
				toStr(Ldrsht);
				toStr(Ldrt);
				toStr(Ldr);
				toStr(Mcr);
				toStr(Mcr2);
				toStr(Mcrr);
				toStr(Mcrr2);
				toStr(Mla);
				toStr(Mls);
				toStr(Mov);
				toStr(Movt);
				toStr(Movw);
				toStr(Mrc);
				toStr(Mrc2);
				toStr(Mrrc);
				toStr(Mrrc2);
				toStr(Mrs);
				toStr(Msr);
				toStr(Mul);
				toStr(Mvn);
				toStr(Orr);
				toStr(Pkhbt);
				toStr(Pkhtb);
				toStr(Pldw);
				toStr(Pld);
				toStr(Pli);
				toStr(Qadd);
				toStr(Qadd16);
				toStr(Qadd8);
				toStr(Qasx);
				toStr(Qdadd);
				toStr(Qdsub);
				toStr(Qsax);
				toStr(Qsub);
				toStr(Qsub16);
				toStr(Qsub8);
				toStr(Rbit);
				toStr(Rev);
				toStr(Rev16);
				toStr(Revsh);
				toStr(Rfeda);
				toStr(Rfedb);
				toStr(Rfeia);
				toStr(Rfeib);
				toStr(Rsb);
				toStr(Rsc);
				toStr(Sadd16);
				toStr(Sadd8);
				toStr(Sasx);
				toStr(Sbc);
				toStr(Sbfx);
				toStr(Sdiv);
				toStr(Sel);
				toStr(Setend);
				toStr(Sha1c);
				toStr(Sha1h);
				toStr(Sha1m);
				toStr(Sha1p);
				toStr(Sha1su0);
				toStr(Sha1su1);
				toStr(Sha256h);
				toStr(Sha256h2);
				toStr(Sha256su0);
				toStr(Sha256su1);
				toStr(Shadd16);
				toStr(Shadd8);
				toStr(Shasx);
				toStr(Shsax);
				toStr(Shsub16);
				toStr(Shsub8);
				toStr(Smc);
				toStr(Smlabb);
				toStr(Smlabt);
				toStr(Smlad);
				toStr(Smladx);
				toStr(Smlal);
				toStr(Smlalbb);
				toStr(Smlalbt);
				toStr(Smlald);
				toStr(Smlaldx);
				toStr(Smlaltb);
				toStr(Smlaltt);
				toStr(Smlatb);
				toStr(Smlatt);
				toStr(Smlawb);
				toStr(Smlawt);
				toStr(Smlsd);
				toStr(Smlsdx);
				toStr(Smlsld);
				toStr(Smlsldx);
				toStr(Smmla);
				toStr(Smmlar);
				toStr(Smmls);
				toStr(Smmlsr);
				toStr(Smmul);
				toStr(Smmulr);
				toStr(Smuad);
				toStr(Smuadx);
				toStr(Smulbb);
				toStr(Smulbt);
				toStr(Smull);
				toStr(Smultb);
				toStr(Smultt);
				toStr(Smulwb);
				toStr(Smulwt);
				toStr(Smusd);
				toStr(Smusdx);
				toStr(Srsda);
				toStr(Srsdb);
				toStr(Srsia);
				toStr(Srsib);
				toStr(Ssat);
				toStr(Ssat16);
				toStr(Ssax);
				toStr(Ssub16);
				toStr(Ssub8);
				toStr(Stc2l);
				toStr(Stc2);
				toStr(Stcl);
				toStr(Stc);
				toStr(Stl);
				toStr(Stlb);
				toStr(Stlex);
				toStr(Stlexb);
				toStr(Stlexd);
				toStr(Stlexh);
				toStr(Stlh);
				toStr(Stmda);
				toStr(Stmdb);
				toStr(Stm);
				toStr(Stmib);
				toStr(Strbt);
				toStr(Strb);
				toStr(Strd);
				toStr(Strex);
				toStr(Strexb);
				toStr(Strexd);
				toStr(Strexh);
				toStr(Strh);
				toStr(Strht);
				toStr(Strt);
				toStr(Str);
				toStr(Sub);
				toStr(Svc);
				toStr(Swp);
				toStr(Swpb);
				toStr(Sxtab);
				toStr(Sxtab16);
				toStr(Sxtah);
				toStr(Sxtb);
				toStr(Sxtb16);
				toStr(Sxth);
				toStr(Teq);
				toStr(Trap);
				toStr(Tst);
				toStr(Uadd16);
				toStr(Uadd8);
				toStr(Uasx);
				toStr(Ubfx);
				toStr(Udf);
				toStr(Udiv);
				toStr(Uhadd16);
				toStr(Uhadd8);
				toStr(Uhasx);
				toStr(Uhsax);
				toStr(Uhsub16);
				toStr(Uhsub8);
				toStr(Umaal);
				toStr(Umlal);
				toStr(Umull);
				toStr(Uqadd16);
				toStr(Uqadd8);
				toStr(Uqasx);
				toStr(Uqsax);
				toStr(Uqsub16);
				toStr(Uqsub8);
				toStr(Usad8);
				toStr(Usada8);
				toStr(Usat);
				toStr(Usat16);
				toStr(Usax);
				toStr(Usub16);
				toStr(Usub8);
				toStr(Uxtab);
				toStr(Uxtab16);
				toStr(Uxtah);
				toStr(Uxtb);
				toStr(Uxtb16);
				toStr(Uxth);
				toStr(Vabal);
				toStr(Vaba);
				toStr(Vabdl);
				toStr(Vabd);
				toStr(Vabs);
				toStr(Vacge);
				toStr(Vacgt);
				toStr(Vadd);
				toStr(Vaddhn);
				toStr(Vaddl);
				toStr(Vaddw);
				toStr(Vand);
				toStr(Vbic);
				toStr(Vbif);
				toStr(Vbit);
				toStr(Vbsl);
				toStr(Vceq);
				toStr(Vcge);
				toStr(Vcgt);
				toStr(Vcle);
				toStr(Vcls);
				toStr(Vclt);
				toStr(Vclz);
				toStr(Vcmp);
				toStr(Vcmpe);
				toStr(Vcnt);
				toStr(Vcvta);
				toStr(Vcvtb);
				toStr(Vcvt);
				toStr(Vcvtm);
				toStr(Vcvtn);
				toStr(Vcvtp);
				toStr(Vcvtt);
				toStr(Vdiv);
				toStr(Vdup);
				toStr(Veor);
				toStr(Vext);
				toStr(Vfma);
				toStr(Vfms);
				toStr(Vfnma);
				toStr(Vfnms);
				toStr(Vhadd);
				toStr(Vhsub);
				toStr(Vld1);
				toStr(Vld2);
				toStr(Vld3);
				toStr(Vld4);
				toStr(Vldmdb);
				toStr(Vldmia);
				toStr(Vldr);
				toStr(Vmaxnm);
				toStr(Vmax);
				toStr(Vminnm);
				toStr(Vmin);
				toStr(Vmla);
				toStr(Vmlal);
				toStr(Vmls);
				toStr(Vmlsl);
				toStr(Vmovl);
				toStr(Vmovn);
				toStr(Vmsr);
				toStr(Vmul);
				toStr(Vmull);
				toStr(Vmvn);
				toStr(Vneg);
				toStr(Vnmla);
				toStr(Vnmls);
				toStr(Vnmul);
				toStr(Vorn);
				toStr(Vorr);
				toStr(Vpadal);
				toStr(Vpaddl);
				toStr(Vpadd);
				toStr(Vpmax);
				toStr(Vpmin);
				toStr(Vqabs);
				toStr(Vqadd);
				toStr(Vqdmlal);
				toStr(Vqdmlsl);
				toStr(Vqdmulh);
				toStr(Vqdmull);
				toStr(Vqmovun);
				toStr(Vqmovn);
				toStr(Vqneg);
				toStr(Vqrdmulh);
				toStr(Vqrshl);
				toStr(Vqrshrn);
				toStr(Vqrshrun);
				toStr(Vqshl);
				toStr(Vqshlu);
				toStr(Vqshrn);
				toStr(Vqshrun);
				toStr(Vqsub);
				toStr(Vraddhn);
				toStr(Vrecpe);
				toStr(Vrecps);
				toStr(Vrev16);
				toStr(Vrev32);
				toStr(Vrev64);
				toStr(Vrhadd);
				toStr(Vrinta);
				toStr(Vrintm);
				toStr(Vrintn);
				toStr(Vrintp);
				toStr(Vrintr);
				toStr(Vrintx);
				toStr(Vrintz);
				toStr(Vrshl);
				toStr(Vrshrn);
				toStr(Vrshr);
				toStr(Vrsqrte);
				toStr(Vrsqrts);
				toStr(Vrsra);
				toStr(Vrsubhn);
				toStr(Vseleq);
				toStr(Vselge);
				toStr(Vselgt);
				toStr(Vselvs);
				toStr(Vshll);
				toStr(Vshl);
				toStr(Vshrn);
				toStr(Vshr);
				toStr(Vsli);
				toStr(Vsqrt);
				toStr(Vsra);
				toStr(Vsri);
				toStr(Vst1);
				toStr(Vst2);
				toStr(Vst3);
				toStr(Vst4);
				toStr(Vstmdb);
				toStr(Vstmia);
				toStr(Vstr);
				toStr(Vsub);
				toStr(Vsubhn);
				toStr(Vsubl);
				toStr(Vsubw);
				toStr(Vswp);
				toStr(Vtbl);
				toStr(Vtbx);
				toStr(Vcvtr);
				toStr(Vtrn);
				toStr(Vtst);
				toStr(Vuzp);
				toStr(Vzip);
				toStr(Addw);
				toStr(Asr);
				toStr(Dcps1);
				toStr(Dcps2);
				toStr(Dcps3);
				toStr(It);
				toStr(Lsl);
				toStr(Lsr);
				toStr(Orn);
				toStr(Ror);
				toStr(Rrx);
				toStr(Subw);
				toStr(Tbb);
				toStr(Tbh);
				toStr(Cbnz);
				toStr(Cbz);
				toStr(Pop);
				toStr(Push);

				toStr(Nop);
				toStr(Yield);
				toStr(Wfe);
				toStr(Wfi);
				toStr(Sev);
				toStr(Sevl);
				toStr(Vpush);
				toStr(Vpop);

				case arm::operation::count: break;
			}
			return UNREACHABLE(const char *);
		};

		return format_to(ctx.out(), opDispatch());
		#undef toStr
	}		
};


#endif //ARM_INS_H