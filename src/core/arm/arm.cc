#include "arm.h"

#include <algorithm>

#include "common/logger.h"

//TODO: write unit tests

namespace arm {
	
	Lifter::Lifter(mmu::mmu & m) {
		mmu = &m;
		if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cap_arm);
			ret != CS_ERR_OK) {
			FATAL("Error creating ARM capstone engine with error code: {}", ret);
		}

		if(cs_err ret = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &cap_thumb);
			ret != CS_ERR_OK) {
			FATAL("Error creating THUMB capstone engine with error code: {}", ret);
		}
	}
	Lifter::Lifter(Lifter&& l) {
		mmu = std::exchange(l.mmu, nullptr);
		cap_arm = l.cap_arm;
		cap_thumb = l.cap_thumb;
	}
	Lifter::~Lifter() {
		if(mmu != nullptr) {
			cs_close(&cap_arm);
			cs_close(&cap_thumb);
		}
	}

	arm_ins_t Lifter::fetch_impl(addr_t pc) {
		if((pc & 1) == 0)
			return fetch_arm_impl(pc);
		else
			return fetch_thumb_impl(pc & (~1U)); // translate pc into address
	}

	arm_ins_t Lifter::fetch_arm_impl(addr_t addr) {
		return fetch_arch_impl<isa::arm>(addr);
	}

	arm_ins_t Lifter::fetch_thumb_impl(addr_t addr) {
		return fetch_arch_impl<isa::thumb>(addr); //pc is already translated into an address in fetch_impl
	}


	template<isa i>
	arm_ins_t Lifter::fetch_arch_impl(addr_t addr) {
		constexpr size_t num_inst = 1;
		constexpr bool is_arm = (i == isa::arm);

		cs_insn *insn;
		size_t count;

		u32 raw_machine_code; //for the log message
		if constexpr(is_arm) {
			u32 machine_code = mmu->read<u32>(addr).read_val;//no static_cast as read_val is already a reg_t aka u32
			raw_machine_code = machine_code;
			count = cs_disasm(cap_arm, reinterpret_cast<u8*>(&machine_code), sizeof(machine_code), addr, num_inst, &insn);
		} else {
			u16 machine_code = static_cast<u16>(mmu->read<u16>(addr).read_val);
			raw_machine_code = machine_code;
			count = cs_disasm(cap_thumb, reinterpret_cast<u8*>(&machine_code), sizeof(machine_code), addr, num_inst, &insn);
		}

		if (count == 0) {
			FATAL("Failure to disassemble {0} machine code into instructions\n"
				  "\taddr: 0x{1:08x}\n"
				  "\t raw: 0x{2:08x}",
				  i,
				  addr,
				  raw_machine_code);
		}

		arm_ins_t ins{};
		ins.addr = addr;

		cs_free(insn, num_inst);

		return ins;
	}



} //namespace arm