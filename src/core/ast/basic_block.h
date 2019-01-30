#ifndef BASIC_BLOCK_H
#define BASIC_BLOCK_H

#include <chrono>
#include <vector>
#include <variant>

#include "common/types.h"



namespace ast::bb {

	template<class T, typename isa_t>
	struct bb_t {
		isa_t				isa; //support for emulation with multiple isa like arm/thumb
		addr_t 				begin_addr;	//raw address, so for arm/thumb don't use 1 bit as T flag
		addr_t 				end_addr;
		std::vector<T> 		ins;
	};

	enum class status {
		empty,
		built,
		optimized,
		jited
	};

	template<class T, typename isa_t>
	struct tracker_t {
		bb_t<T, isa_t> bb;
		status bb_status = status::empty;

		//TODO: add timestamps to track how hot/cold
		//this basic block is

		//TODO: JIT smart pointer for function pointers
		//for a future recompiler
	};

} //namespace ast

#endif //BASIC_BLOCK_H