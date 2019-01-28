#ifndef AST_H
#define AST_H

#include <chrono>
#include <vector>
#include <variant>

#include "common/types.h"

namespace ast {

	template<class T, typename isa_t>
	struct basic_block_t {
		isa_t				isa; //support for emulation with multiple isa like arm/thumb
		addr_t 				begin_addr;	//raw address, so for arm/thumb don't use 1 bit as T flag
		addr_t 				end_addr;
		std::vector<T> 		ins;
	};

	template<class T, typename isa_t>
	struct basic_block_tracker_t {
		basic_block_t<T, isa_t> bb;

		//TODO: add timestamps to track how hot/cold
		//this basic block is

		//TODO: JIT smart pointer for function pointers
		//for a future recompiler
	}

} //namespace ast

#endif