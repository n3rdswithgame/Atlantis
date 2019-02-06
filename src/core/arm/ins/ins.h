#ifndef ARM_INS_H
#define ARM_INS_H

#include <utility>

#include "core/arm/cpu.h"

#include "common/mask.h"
#include "common/types.h"


namespace arm::ins {
	namespace mask {
		#define C(x)					(static_cast<u32>(x))
		#define MASK(x,n)				(C(x) & C((1 << (n))-1))
		#define BIT_PLACE(x,e,b)		(MASK(x, e-b+1) << b)
		
		//alias all of the masking tools into here
		//otherwise everything would have to be prefixed
		//with "::mask", and this nested namespace is devoted
		//to just masks so having the mask tools in here is not actually a problem
		using namespace ::mask;

		//all of these are taken from teh ARM Archatecture Reference Manual,
		//Issue I, Chapter A3

		using DataProcessing 		= combine<
										bit_range<0b000, 27, 25>
									>;

		using DPImmShift			= combine<
										DataProcessing,
										bit<0, 4>
									>;

		using DPRegShift			= combine<
										DataProcessing,
										bit<0, 7>,
										bit<1, 4>
									>;

		using DPImm					= combine<
										DataProcessing,
										bit<1, 7>,
										bit<1, 4>
									>;

		using ImmtoStatusReg		= combine<
										bit_range<0b00110, 27, 23>,
										bit_range<0b10, 21, 20>
									>;

		using LSImmOff				= combine<
										bit_range<0b010, 27, 25>
									>;

		using LSRegOff				= combine<
										bit_range<0b011, 27, 25>,
										bit<0, 4>
									>;

		using LSExtra				= combine<
										bit_range<0b000, 27, 25>,
										bit<1, 7>,
										bit<1, 4>
									>;

		using SVC					= combine<
										bit_range<0b1111, 27, 24>
									>;

		using BlockTransfer 		= combine<
										bit_range<0b100, 27, 25>
									>;

		using BranchImm				= combine<
										bit_range<0b101, 27, 25>
									>;
		using Media					= combine<
										bit_range<0b011, 27, 25>,
										bit<1, 4>
									>;

		using Multiply				= combine<
										bit_range<0b000, 27, 25>,
										bit<1, 7>,
										bit<1, 4>
									>;

		using CP_LS_DoubleRegTrans	= combine<
										bit_range<0b110, 27, 25>
									>;

		using CP_DataProcessing		= combine<
										bit_range<0b1110, 27, 24>,
										bit<0, 4>
									>;

		using CP_RegTrans			= combine<
										bit_range<0b1110, 27, 24>,
										bit<1, 4>
									>;

		using Misc_1				= combine<
										bit_range<0b00010, 27, 23>,
										bit<0, 20>,
										bit<0, 4>
									>;

		using Misc_2				= combine<
										bit_range<0b00010, 27, 23>,
										bit<0, 20>,
										bit<0, 7>,
										bit<1, 4>
									>;

		using Unconditional			= combine<
										bit_range<0b1111, 31, 28>
									>;

		using ArchitectuallyUndef	= combine<
										bit_range<0b01111111, 27, 20>,
										bit_range<0b1111, 7, 4>
									>;

		using Undef					= combine<
										bit_range<0b00110, 27, 23>,
										bit_range<0b00, 21, 20>
									>;

	}//namespace arm::ins::mask

	namespace parts {
		enum class cond : u32 {
		//taken straight form the ARM Archatecture Reference Manual

												 // meaning								flags

		eq = mask::bit_range<0b0000, 31, 28>::m, // Equal 								Z set
		ne = mask::bit_range<0b0001, 31, 28>::m, // Not equal 							Z clear
		cs = mask::bit_range<0b0010, 31, 28>::m, // Carry set/unsigned higher or same 	C set
		cc = mask::bit_range<0b0011, 31, 28>::m, // Carry clear/unsigned lower 			C clear
		mi = mask::bit_range<0b0100, 31, 28>::m, // Minus/negative 						N set
		pl = mask::bit_range<0b0101, 31, 28>::m, // Plus/positive or zero 				N clear
		vs = mask::bit_range<0b0110, 31, 28>::m, // Overflow 							V set
		vc = mask::bit_range<0b0111, 31, 28>::m, // No overflow 						V clear
		hi = mask::bit_range<0b1000, 31, 28>::m, // Unsigned higher 					C set and Z clear
		ls = mask::bit_range<0b1001, 31, 28>::m, // Unsigned lower or same 				C clear or Z set
		ge = mask::bit_range<0b1010, 31, 28>::m, // Signed greater than or equal 		N set and V set, or N clear and V clear (N == V)
		lt = mask::bit_range<0b1011, 31, 28>::m, // Signed less than 					N set and V clear, or N clear and V set (N != V)
		gt = mask::bit_range<0b1100, 31, 28>::m, // Signed greater than 				Z clear, and (N and V are both set or clear) (Z == 0,N == V)
		le = mask::bit_range<0b1101, 31, 28>::m, // Signed less than or equal 			Z set, or N set and V clear, or N clear and V set (Z == 1 or N != V)
		al = mask::bit_range<0b1110, 31, 28>::m, // Always (unconditional) 				-

		// the invalid conditional is only used on instructions that can't be conditional,
		// so in the lifter those will just be tagged as AL

		hs = cs,
		lo = cc,
	};

		enum class dp {
			And		= mask::bit_range<0b0000, 24, 21>::m,
			Eor		= mask::bit_range<0b0001, 24, 21>::m,
			Sub		= mask::bit_range<0b0010, 24, 21>::m,
			Rsb		= mask::bit_range<0b0011, 24, 21>::m,
			Add		= mask::bit_range<0b0100, 24, 21>::m,
			Adc		= mask::bit_range<0b0101, 24, 21>::m,
			Sbc		= mask::bit_range<0b0110, 24, 21>::m,
			Rsc		= mask::bit_range<0b0111, 24, 21>::m,
			Tst		= mask::bit_range<0b1000, 24, 21>::m,
			Teq		= mask::bit_range<0b1001, 24, 21>::m,
			Cmp		= mask::bit_range<0b1010, 24, 21>::m,
			Cmn		= mask::bit_range<0b1011, 24, 21>::m,
			Orr		= mask::bit_range<0b1100, 24, 21>::m,
			Mov		= mask::bit_range<0b1101, 24, 21>::m,
			Bic		= mask::bit_range<0b1110, 24, 21>::m,
			Mvn		= mask::bit_range<0b1111, 24, 21>::m,
		};

		enum class status {
			update = mask::bit<1, 20>::m,
			ignore = mask::bit<0, 20>::m,
		};

		enum class shift {
			lsl = mask::bit_range<0b00, 6, 5>::m,
			lsr = mask::bit_range<0b01, 6, 5>::m,
			asl = mask::bit_range<0b10, 6, 5>::m,
			asr = mask::bit_range<0b01, 6, 5>::m,
		};
	}//namespace arm::ins::flags

	template<u32 Armv, typename Mask>
	struct ArmInst : Mask {
		constexpr static u32 ver = Armv;
		constexpr static u32 getVer() {
			return ver;
		}

		bool used = false;
		u32 value = 0;

		constexpr ArmInst() { 
			//default used to false
			used = false;
		}
		constexpr ArmInst(u32 v) {
			used = true;
			value = v;
		}

		constexpr u32 getVal() const {
			return false;
		}

		constexpr operator u32() const {
			return getVal();
		}

	protected:
		constexpr u32 getConditionalVal() const {
		//for the many struct below, only contribute to the encoded
		//value if its used
			if(used) {
				return value;
			} else {
				return 0;
			}
		}

		constexpr u32 getConditionalVer() const {
		//for the many struct below, only contribute to the versioning
		//if your encoding is used
			if(used)
				return ver;
			else
				return 0;
		}
	};

	template<typename Arminst, parts::cond cond=parts::cond::eq>
	struct Conditional : Arminst{
		using Arminst::Arminst;

		using Arminst::getVer;

		constexpr u32 getVal() const {
			return static_cast<u32>(cond) | Arminst::operator u32();
		}

		constexpr operator u32() const {
			return getVal();
		}
	};

	// DO NOT USE. This is only left to show how to implement an instruction / 
	// group of instrucitons that has multiple possible encodigns depending on 
	// args
	//
	//template<typename... ArmInsts>
	//struct Many : ArmInsts... {
	//	//import all of the ctors for use in above
	//	//ctor "spealiziation"
	//	template<typename... Args>
	//	constexpr Many(Args... args) : ArmInsts(args...) {}

	//	constexpr operator u32() const {
	//	//shadow the operator u32 in the super classes
	//		return (ArmInsts::getConditionalVal() | ...);
	//	}

	//	constexpr u32 getVer() const {
	//	//As mentioned above, this will or all of the conditional versions together,
	//		return (ArmInsts::getConditionalVer() | ...);
	//	}
	//};

	constexpr u32 RdRmEnc(cpu::reg rd, cpu::reg rn) {
		return BIT_PLACE(rn, 19, 16) | BIT_PLACE(rd, 15, 12);
	}

	constexpr u32 ImmShiftEnc(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, u8 shift_imm) {
		return RdRmEnc(rd,rn) | BIT_PLACE(shift_imm, 11, 7) | C(sh) | C(shift_imm) | BIT_PLACE(rm, 3, 0);
	}

	template<u32 Armv, parts::dp op, parts::status s>
	struct DPImmShift : ArmInst<Armv,mask::DPImmShift> {
		constexpr DPImmShift() : ArmInst<Armv, mask::DPImmShift>()
		{}

		constexpr DPImmShift(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, u8 shift_imm) :
			ArmInst<Armv, mask::DPImmShift>(C(op) | C(s) | ImmShiftEnc(rd, rn, rm, sh, shift_imm))
		{}
	};
	
	constexpr u32 RegShiftEnc(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, cpu::reg rs) {
		return RdRmEnc(rd, rn) | BIT_PLACE(rs, 11, 8) | C(sh) | BIT_PLACE(rm, 3, 0);
	}

	template<u32 Armv, parts::dp op, parts::status s>
	struct DPRegShift : ArmInst<Armv,mask::DPRegShift> {
		constexpr DPRegShift() : ArmInst<Armv, mask::DPRegShift>()
		{}

		constexpr DPRegShift(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, cpu::reg rs) : 
			ArmInst<Armv, mask::DPRegShift>(C(op) | C(s) | RegShiftEnc(rd, rn, rm, sh, rs))
		{}
	};


	constexpr u32 RotImmEnc(u8 rot, u8 imm) {
		return BIT_PLACE(rot, 11, 8) | BIT_PLACE(imm, 7, 0);
	}

	template<u32 Armv, parts::dp op, parts::status s>
	struct DPImm : ArmInst<Armv,mask::DPImm> {
		constexpr DPImm() : ArmInst<Armv, mask::DPImm>()
		{}

		constexpr DPImm(cpu::reg rd, cpu::reg rn, u8 rot, u8 imm) : 
			ArmInst<Armv, mask::DPImm>(C(op) | C(s) | RotImmEnc(rot, imm))
		{}	
	};

	constexpr cpu::reg DPDefaultRN(parts::dp op, cpu::reg rd) {
		if(op == parts::dp::Mov)
			return cpu::reg::r0;
		return rd;
	}

	template<u32 Armv, parts::dp op, parts::status s>
	struct DataProcessing : DPImmShift<Armv, op, s>,
							DPRegShift<Armv, op, s>,
							DPImm<Armv, op, s>
	{
		using DPImmShift = arm::ins::DPImmShift<Armv, op, s>;
		using DPRegShift = arm::ins::DPRegShift<Armv, op, s>;
		using DPImm 	 = arm::ins::DPImm<Armv, op, s>;
		
		constexpr DataProcessing(cpu::reg rd,              cpu::reg rm) :
			DataProcessing(rd, DPDefaultRN(op, rd), rm)
		{}

		constexpr DataProcessing(cpu::reg rd, cpu::reg rn, cpu::reg rm) :
			DataProcessing(rd, rn, rm, parts::shift::lsl, 0)
		{}

		constexpr DataProcessing(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, u8 shift_imm) :
			DPImmShift(rd, rn, rm, sh, shift_imm), DPRegShift(), DPImm()
		{}

		//--------------------------------------------------------------------------------------------

		constexpr DataProcessing(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, cpu::reg rs) :
			DPImmShift(), DPRegShift(rd, rn, rm, sh, rs), DPImm()
		{}

		//--------------------------------------------------------------------------------------------

		constexpr DataProcessing(cpu::reg rd,              u8 rot, u8 imm) :
			DataProcessing(rd, rd, rot, imm)
		{}

		constexpr DataProcessing(cpu::reg rd, cpu::reg rn, u8 rot, u8 imm) :
			DPImmShift(), DPRegShift(), DPImm(rd, rn, rot, imm)
		{}

		constexpr operator u32() const {
		//shadow the operator u32 in the super classes
			return DPImmShift::getConditionalVal()
					| DPRegShift::getConditionalVal()
					| DPImm::getConditionalVal();
		}

		constexpr u32 getVer() const {
		//As mentioned above, this will or all of the conditional versions together,
			return DPImmShift::getConditionalVer()
					| DPRegShift::getConditionalVer()
					| DPImm::getConditionalVer();
		}
	};

	#define glue(x,y) x ## y

	#define DefDPInstSet(ins)																							\
		using glue(ins,  ) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::al>;	\
		using glue(ins,eq) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::eq>;	\
		using glue(ins,ne) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::ne>;	\
		using glue(ins,cs) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::cs>;	\
		using glue(ins,cc) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::cc>;	\
		using glue(ins,mi) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::mi>;	\
		using glue(ins,pl) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::pl>;	\
		using glue(ins,vs) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::vs>;	\
		using glue(ins,vc) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::vc>;	\
		using glue(ins,hi) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::hi>;	\
		using glue(ins,ls) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::ls>;	\
		using glue(ins,ge) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::ge>;	\
		using glue(ins,lt) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::lt>;	\
		using glue(ins,gt) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::gt>;	\
		using glue(ins,le) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::ignore>, parts::cond::le>;	\
																														\
		using glue(ins,S) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::al>;		\
		using glue(ins,eqS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::eq>;	\
		using glue(ins,neS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::ne>;	\
		using glue(ins,csS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::cs>;	\
		using glue(ins,ccS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::cc>;	\
		using glue(ins,miS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::mi>;	\
		using glue(ins,plS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::pl>;	\
		using glue(ins,vsS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::vs>;	\
		using glue(ins,vcS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::vc>;	\
		using glue(ins,hiS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::hi>;	\
		using glue(ins,lsS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::ls>;	\
		using glue(ins,geS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::ge>;	\
		using glue(ins,ltS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::lt>;	\
		using glue(ins,gtS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::gt>;	\
		using glue(ins,leS) = Conditional<DataProcessing<1, parts::dp::ins, parts::status::update>, parts::cond::le>

	DefDPInstSet(And);
	DefDPInstSet(Eor);
	DefDPInstSet(Sub);
	DefDPInstSet(Rsb);
	DefDPInstSet(Add);
	DefDPInstSet(Adc);
	DefDPInstSet(Sbc);
	DefDPInstSet(Rsc);
	DefDPInstSet(Tst);
	DefDPInstSet(Teq);
	DefDPInstSet(Cmp);
	DefDPInstSet(Cmn);
	DefDPInstSet(Orr);
	DefDPInstSet(Mov);
	DefDPInstSet(Bic);
	DefDPInstSet(Mvn);

	//16 down, ~130 to go

} //namespace arm::ins

#endif //ARM_INS_H