#ifndef ARM_INS_H
#define ARM_INS_H

#include <utility>

#include "core/arm/cpu.h"

#include "common/bit/mask.h"
#include "common/types.h"


namespace arm::ins {
	namespace mask {
		#define C(x)					(static_cast<u32>(x))
		#define MASK(x,n)				(C(x) & C((1 << (n))-1))
		#define BIT_PLACE(x,e,b)		(MASK(x, e-b+1) << b)
		
		//using namespace ::bit::mask stopped working for some reason
		//TODO: figure out why using namespace stopped working
		using ::bit::mask::combine;
		using ::bit::mask::bit;
		using ::bit::mask::bit_range;
		using ::bit::mask::lower;

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

		using BranchImm				= combine<
										bit_range<0b101, 27, 25>
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
		ge = mask::bit_range<0b1010, 31, 28>::m, // Signed greater than or equal 		(N == V)
		lt = mask::bit_range<0b1011, 31, 28>::m, // Signed less than 					(N != V)
		gt = mask::bit_range<0b1100, 31, 28>::m, // Signed greater than 				(Z == 0,N == V)
		le = mask::bit_range<0b1101, 31, 28>::m, // Signed less than or equal 			(Z == 1 or N != V)
		al = mask::bit_range<0b1110, 31, 28>::m, // Always (unconditional) 				always

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

		enum class link {
			link	= mask::bit<1, 24>::m,
			ignore	= mask::bit<0, 24>::m,
		};

		enum class mem {
			load 	= mask::bit<1, 20>::m,
			store 	= mask::bit<0, 20>::m,
		};

		enum class priv_status {
			curr_bank	= mask::bit<0, 22>::m,
			user 	 	= mask::bit<1, 22>::m,
		};

		enum class write_back {
			wb 		= mask::bit<1, 21>::m,
			ignore	= mask::bit<0, 21>::m,
		};

		enum class bt_adressingmode {
			da = mask::bit_range<0b00, 24, 23>::m,
			ia = mask::bit_range<0b01, 24, 23>::m,
			db = mask::bit_range<0b10, 24, 23>::m,
			ib = mask::bit_range<0b11, 24, 23>::m,
		};

		enum class index_addressing {
			post = mask::bit<0, 24>::m,
			pre  = mask::bit<1, 24>::m,
		};

		enum class mem_size {
			byte = mask::bit<1,22>::m,
			word = mask::bit<0,22>::m,
		};

		enum class apply_off {
			add = mask::bit<1,23>::m,
			sub = mask::bit<0,23>::m,
		};
	}//namespace arm::ins::parts

	namespace types {

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
	
		template<typename Arminst, parts::cond cond>
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
	
		// TODO: figure out how to SFINAE between the two constructors in many_wrapper
		// on whether the template class has a constructor that can accept that arguments
		// This will clean up the DataProcessing class
		
		//template<typename T>
		//struct many_wrapper : T {
		//	template<typename... Args>
		//	many_wrapper(Args&&... args) : T(std::forward<Args>(args)...) {}
	
		//	template<typename... Args>
		//	many_wrapper(Args&&... args) : T() {}
		//}
	
		//template<typename... ArmInsts>
		//struct Many : many_wrapper<ArmInsts>... {
		//	//import all of the ctors for use in above
		//	//ctor "spealiziation"
		//	template<typename... Args>
		//	constexpr Many(Args... args) : many_wrapper<ArmInsts>(args...) {}
	
		//	constexpr operator u32() const {
		//	//shadow the operator u32 in the super classes
		//		return (ArmInsts::getConditionalVal() | ...);
		//	}
	
		//	constexpr u32 getVer() const {
		//	//As mentioned above, this will or all of the conditional versions together,
		//		return (ArmInsts::getConditionalVer() | ...);
		//	}
		//};
	
		constexpr u32 RdRnEnc(cpu::reg rd, cpu::reg rn) {
			return BIT_PLACE(rn, 19, 16) | BIT_PLACE(rd, 15, 12);
		}
	
		constexpr u32 ImmShiftEnc(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, u8 shift_imm) {
			return RdRnEnc(rd,rn) | BIT_PLACE(shift_imm, 11, 7) | C(sh) | C(shift_imm) | BIT_PLACE(rm, 3, 0);
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
			return RdRnEnc(rd, rn) | BIT_PLACE(rs, 11, 8) | C(sh) | BIT_PLACE(rm, 3, 0);
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
				ArmInst<Armv, mask::DPImm>(C(op) | C(s) | RdRnEnc(rd, rn) | RotImmEnc(rot, imm))
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
			using DPImmShift = arm::ins::types::DPImmShift<Armv, op, s>;
			using DPRegShift = arm::ins::types::DPRegShift<Armv, op, s>;
			using DPImm 	 = arm::ins::types::DPImm<Armv, op, s>;
			
			constexpr DataProcessing(cpu::reg rd,              cpu::reg rm) :
				DataProcessing(rd, DPDefaultRN(op, rd), rm)
			{}
	
			constexpr DataProcessing(cpu::reg rd, cpu::reg rn, cpu::reg rm) :
				DataProcessing(rd, rn, rm, parts::shift::lsl, 0)
			{}
	
			constexpr DataProcessing(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, u8 shift_imm) :
				DPImmShift(rd, rn, rm, sh, shift_imm),
				DPRegShift(),
				DPImm()
			{}
	
			//--------------------------------------------------------------------------------------------
	
			constexpr DataProcessing(cpu::reg rd, cpu::reg rn, cpu::reg rm, parts::shift sh, cpu::reg rs) :
				DPImmShift(),
				DPRegShift(rd, rn, rm, sh, rs),
				DPImm()
			{}
	
			//--------------------------------------------------------------------------------------------
	
			constexpr DataProcessing(cpu::reg rd,              u8 rot, u8 imm) :
				DataProcessing(rd, rd, rot, imm)
			{}
	
			constexpr DataProcessing(cpu::reg rd, cpu::reg rn, u8 rot, u8 imm) :
				DPImmShift(),
				DPRegShift(),
				DPImm(rd, rn, rot, imm)
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

		constexpr u32 BImmEnc(s32 off) {
			u32 val = static_cast<u32>(off >> 2);
			return val & mask::lower<24>::m;
		}

		template<u32 Armv, parts::link l>
		struct BranchImm : ArmInst<Armv, mask::BranchImm> {
			constexpr BranchImm(s32 off) : ArmInst<Armv, mask::BranchImm>(BImmEnc(off)) 
			{}
		};

		constexpr u32 BlockTransEnc(parts::bt_adressingmode am, parts::priv_status s,
			parts::write_back w, parts::mem l, cpu::reg rn)
		{
			return C(am) | C(s) | C(l) | C(w) | BIT_PLACE(rn, 19, 16);
		}

		template<typename... Args>
		constexpr u32 RegListEnc(Args... args) {
			static_assert((std::is_same_v<Args, cpu::reg> && ...), "Reglist must inlcude only register");
			return ((1 << static_cast<u32>(args)) | ...);
		}

		template<u32 Armv, parts::bt_adressingmode am, parts::priv_status s, parts::write_back w, parts::mem l>
		struct BlockTransfer : ArmInst<Armv, mask::BlockTransfer> {
			template<typename... Args>
			BlockTransfer(cpu::reg rn, Args... args) : 
				ArmInst<Armv, mask::BlockTransfer>( BlockTransEnc(am, s, w, l, rn) | ReglistEnc(args...))
			{}
		};

		//template for all of the ldm instructions
		template<u32 Armv, parts::bt_adressingmode am, parts::priv_status s, parts::write_back w>
		using Ldmr = BlockTransfer<Armv, am, s, w, parts::mem::load>;

		//template for all of the stm instructions
		template<u32 Armv, parts::bt_adressingmode am, parts::priv_status s, parts::write_back w>
		using Stmr = BlockTransfer<Armv, am, s, w, parts::mem::store>;

		template<u32 Armv>
		struct Svc : ArmInst<Armv, mask::SVC> {
			Svc(u32 num) : ArmInst<Armv, mask::SVC>(mask::lower<24>::apply(num))
			{}
		};

		constexpr u32 UEnc(s32 imm) {
			if(imm < 0)
				return mask::bit<1, 23>::m;
			else
				return mask::bit<0, 23>::m;
		}


		template<u32 Armv, parts::index_addressing p, parts::mem_size b, parts::priv_status w, parts::mem l>
		struct LSImm : ArmInst<Armv, mask::LSImmOff> {
			LSImm(cpu::reg rd, cpu::reg rn, s32 imm) :
				ArmInst<Armv, mask::LSImmOff>(C(p) | UEnc(imm) | C(b) | C(w) | C(l) | RdRnEnc(rd, rn) | mask::lower<12>::apply(C(imm)))
			{}
		};

		template<u32 Armv, parts::index_addressing p, parts::mem_size b, parts::priv_status w, parts::mem l>
		struct LSRegOff : ArmInst<Armv, mask::LSRegOff> {
			LSRegOff(cpu::reg rd, cpu::reg rn, parts::apply_off u, cpu::reg rm, parts::shift sh, s8 shift) :
				ArmInst<Armv, mask::LSRegOff>(C(p) | C(u) | C(b) | C(w) | C(l) 
					| RdRnEnc(rd, rn) | BIT_PLACE(shift, 11, 7) | C(sh) | C(rm))
			{}
		};

		template<u32 Armv, parts::index_addressing p, parts::mem_size b, parts::priv_status w, parts::mem l>
		struct LS : LSImm<Armv, p, b, w, l>,
					LSRegOff<Armv, p, b, w, l>
		{
			using LSImm 	= arm::ins::types::LSImm<Armv, p, b, w, l>;
			using LSRegOff 	= arm::ins::types::LSRegOff<Armv, p, b, w, l>;
			using apply_off = parts::apply_off;

			LS(cpu::reg rd, cpu::reg rn) :
				LS(rd, rn, 0)
			{}

			LS(cpu::reg rd, cpu::reg rn, s32 imm) :
				LSImm(rd,rn, imm),
				LSRegOff()
			{}

			//-----------------------------------------------------------------------------------

			LS(cpu::reg rd, cpu::reg rn, parts::apply_off u, cpu::reg rm, parts::shift sh, s8 shift) :
				LSImm(),
				LSRegOff(rd, rn, u, rm, sh, shift)
			{}
		};

	} //namespace arm::ins::types

	//define ins and ins_cond<cond>
	#define DEF_INST(ins, ...)																					\
		using ins = types::Conditional< __VA_ARGS__ , parts::cond::al>;											\
		template<parts::cond cond>																				\
		using ins ##_cond = types::Conditional< __VA_ARGS__ , cond>


	//define ins(_cond<cond>) and insS(_cond<cond>)
	#define DP__INST(i)																							\
		DEF_INST(i, types::DataProcessing<1, parts::dp::i, parts::status::ignore>);								\
		DEF_INST(i ## S, types::DataProcessing<1, parts::dp::i, parts::status::update>)


	#define BDT(ins, base, Armv, btam, priv)																	\
		template<parts::write_back w>																			\
		using ins = types::Conditional< base< Armv, btam, priv, w>, parts::cond::al>;							\
		template<parts::write_back w, parts::cond cond>															\
		using ins ## _cond = types::Conditional< base< Armv, btam, priv, w>, cond>

		
	#define BDT_INST(i, base)																					\
		BDT(i, 				base, 1, parts::bt_adressingmode::ia, parts::priv_status::curr_bank);				\
		BDT(i ## da, 		base, 1, parts::bt_adressingmode::da, parts::priv_status::curr_bank);				\
		BDT(i ## ia, 		base, 1, parts::bt_adressingmode::ia, parts::priv_status::curr_bank);				\
		BDT(i ## db, 		base, 1, parts::bt_adressingmode::db, parts::priv_status::curr_bank);				\
		BDT(i ## ib, 		base, 1, parts::bt_adressingmode::ib, parts::priv_status::curr_bank);				\
		BDT(i ## _priv	, 	base, 1, parts::bt_adressingmode::ia, parts::priv_status::user);					\
		BDT(i ## da_priv, 	base, 1, parts::bt_adressingmode::da, parts::priv_status::user);					\
		BDT(i ## ia_priv, 	base, 1, parts::bt_adressingmode::ia, parts::priv_status::user);					\
		BDT(i ## db_priv, 	base, 1, parts::bt_adressingmode::db, parts::priv_status::user);					\
		BDT(i ## ib_priv, 	base, 1, parts::bt_adressingmode::ib, parts::priv_status::user)



	DP__INST	(Adc);
	DP__INST	(Add);
	DP__INST	(And);
	DP__INST	(Bic);
	DP__INST	(Cmn);
	DP__INST	(Cmp);
	DP__INST	(Eor);
	DP__INST	(Mov);
	DP__INST	(Mvn);
	DP__INST	(Orr);
	DP__INST	(Rsb);
	DP__INST	(Rsc);
	DP__INST	(Sbc);
	DP__INST	(Sub);
	DP__INST	(Teq);
	DP__INST	(Tst);

	DEF_INST	(B,  types::BranchImm<1, parts::link::ignore>);
	DEF_INST	(Bl, types::BranchImm<1, parts::link::link	>);

	BDT_INST	(Ldm, types::Ldmr);
	BDT_INST	(Stm, types::Stmr);

	DEF_INST	(Svc, types::Svc<1>);
	//21 down, 27 more for Armv4, 93 more for Armv6

	#undef BDT_INST
	#undef BDT
	#undef DP__INST
	#undef DEF_INST

} //namespace arm::ins

#endif //ARM_INS_H