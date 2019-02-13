#ifndef DEC_ARM_BRANCHING_H
#define DEC_ARM_BRANCHING_H

#include "core/arm/arm.h"

#include "common/types.h"

namespace arm::dec::arm {
	//Reminder this decodes only ARM branches with immediates
	inline status branchImm(addr_t addr, u32 ins, out<::arm::ins_t> i) {
		u32 off = static_cast<u32>(bit::mask::lower<24>::extract(ins));
		if(bit::mask::bit<1,23>::test(off)) {
			//sign extend if needed (ie bit 23 of the offset is 1)
			off |= bit::mask::bit_range<0b11111111, 31, 24>::m;
		}
		//for ARM/thumb, pc is for the decoding ins on the executing ins,
		//so pc is always 2 instructions ahead of the the addr
		addr_t pc = addr + 2 * 4;//4 is the size of an ARM instruction
		
		//in a branch imm, offset lowest 2 bits are shifted away to increase
		//branch target range

		//both of these are unsigned types, and luckily according to the standard
		//and thankfully unsigned types "overflow" is well defined in the standard
		//[basic.fundamental] item 4
		addr_t target = pc + (off<<2);

		//TODO: rewrite using the enum in ins.h
		if(bit::mask::bit<1,24>::test(ins)) {
			i.op = ::arm::operation::Bl;
		} else {
			i.op = ::arm::operation::B;
		}

		i.operands = make_op_ui(target);

		return status::success;
	}
} //namespace arm::dec::arm

#endif //DEC_ARM_BRANCHING_H