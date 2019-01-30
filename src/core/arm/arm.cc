#include "arm.h"

#include <algorithm>

#include "common/logger.h"

namespace arm {

	arm_ins_t Lifter::fetch_impl(addr_t addr) {
		arm_ins_t inst{};
		inst.addr = addr;
		return inst;
	}

	
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

} //namespace arm