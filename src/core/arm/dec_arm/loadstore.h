#ifndef DEC_ARM_LOAD_STORE_H
#define DEC_ARM_LOAD_STORE_H

#include "status.h"

#include "core/arm/arm.h"

#include "common/types.h"

namespace arm::dec::a {
	//only handle word/byte loads/stores as halfword have seperate encoding
	inline status parseBits_LSWB(addr_t, u32, out<arm::ins_t>);

	inline status LSWBImm(addr_t addr, u32 ins, out<arm::ins_t> i) {
		return status::nomatch;
	}
	inline status LSWBRegOff(addr_t addr, u32 ins, out<arm::ins_t> i) {
		return status::nomatch;
	}

	inline status parseBits_LSWB(addr_t, u32, out<arm::ins_t>) {
		
	}

	//only handle halfword loads/stores as word/byte have seperate encoding
	//TODO: halfwords

} //namespace arm::dec::a
#endif //DEC_ARM_LOAD_STORE_H