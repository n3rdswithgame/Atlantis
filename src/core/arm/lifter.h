#ifndef ARM_LIFTER_H
#define ARM_LIFTER_H

#include "cpu.h"
#include "ins.h"

#include "core/ast/ast.h"
#include "core/mmu.h"


#include <capstone/capstone.h>
	


namespace arm {
	using basic_block			= ast::bb::bb_t<ins_t, isa>;
	using basic_block_tracker	= ast::bb::tracker_t<ins_t, isa>;

	template<isa i>
	ins_t decode(cs_insn*);

	//these will be instantiated in lifter.cc
	//extern template ins_t decode<isa::arm>(cs_insn*);
	//extern template ins_t decode<isa::thumb>(cs_insn*);

	template<typename Region>
	class Lifter : public ast::Lifter<Lifter<Region>, ins_t, isa, mmu::mmu<Region>> {

		friend class ast::Lifter<Lifter<Region>, ins_t, isa, mmu::mmu<Region>>;

		using ast_Lifter = ast::Lifter<Lifter<Region>, ins_t, isa, mmu::mmu<Region>>;
		
		//TODO: Profile 2 different capstone instances
		//vs 1 and switching the isa as needed
		csh cap_arm;
		csh cap_thumb;


	public:
		Lifter(mmu::mmu<Region> &m) : ast_Lifter(m) {
			if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cap_arm);
				ret != CS_ERR_OK) {
				FATAL("Error creating ARM capstone engine with error code: {}", ret);
			}
			if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &cap_thumb);
				ret != CS_ERR_OK) {
				FATAL("Error creating THUMB capstone engine with error code: {}", ret);
			}
			cs_option(cap_arm, CS_OPT_DETAIL, CS_OPT_ON);
			cs_option(cap_thumb, CS_OPT_DETAIL, CS_OPT_ON);
		}

		Lifter(Lifter&& l) {
			cap_arm   = l.cap_arm;
			cap_thumb = l.cap_thumb;
		}

		~Lifter() {
			if(ast_Lifter::isValid()) {
				cs_close(&cap_arm);
				cs_close(&cap_thumb);
			}
		}

	private:
		ins_t fetch_impl(addr_t pc) {
			if((pc & 1) == 0)
				return fetchArm_impl(pc);
			else
				return fetchThumb_impl(pc & (~1U)); // translate pc into address
		}
		
		ins_t fetchArm_impl(addr_t addr) {
			return fetchArch_impl<isa::arm>(addr);
		}

		ins_t fetchThumb_impl(addr_t addr) {
			//pc is already translated into an address in fetch_impl
			return fetchArch_impl<isa::thumb>(addr);
		}
		
		template<isa i>
		ins_t fetchArch_impl(addr_t addr) {
			constexpr size_t num_inst = 1;
			constexpr bool is_arm = (i == isa::arm);
	
			cs_insn *insn;
			size_t count;
	
			u32 raw_machine_code; //for the log message
			if constexpr(is_arm) {
				u32 machine_code = ast_Lifter::template mmuFetch<u32>(addr).read_val;//no static_cast as read_val is already a reg_t aka u32
				raw_machine_code = machine_code;
				count = cs_disasm(cap_arm, reinterpret_cast<u8*>(&machine_code),
					sizeof(machine_code), addr, num_inst, &insn);
			} else {
				addr |= 1;// to ensure that the instructions will diassemble correctly 
				//for any pc relative op, like a str/ldm rel pc, or branch rel imm
				u16 machine_code = static_cast<u16>(ast_Lifter::template mmuFetch<u16>(addr).read_val);
				raw_machine_code = machine_code;
				count = cs_disasm(cap_thumb, reinterpret_cast<u8*>(&machine_code),
					sizeof(machine_code), addr, num_inst, &insn);
			}
	
			if (count == 0) {
				FATAL("Failure to disassemble {0} machine code into instructions\n"
					  "\taddr: 0x{1:08x}\n"
					  "\t raw: 0x{2:08x}",
					  i,
					  addr,
					  raw_machine_code);
				return {};
			}
	
			ins_t ins = decode<i>(insn);
			ins.addr = addr;
	
			cs_free(insn, num_inst);
	
			return ins;
		}
	};
} //namespace arm

#endif //ARM_LIFTER_H