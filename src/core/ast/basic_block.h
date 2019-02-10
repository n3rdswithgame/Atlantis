#ifndef BASIC_BLOCK_H
#define BASIC_BLOCK_H

#include <algorithm>
#include <chrono>
#include <optional>
#include <vector>
#include <variant>

#include "common/types.h"


namespace ast::bb {

	template<class Ins_t, typename Isa_t>
	struct bb_t {
		using ins_t = Ins_t;
		using isa_t = Isa_t;

		isa_t				isa; //support for emulation with multiple isa like arm/thumb
		std::vector<ins_t> 	ins;
		addr_t 				begin_addr;	//raw address, so for arm/thumb don't use 1 bit as T flag
		addr_t 				end_addr;

		bb_t() = default;
		bb_t(addr_t start, addr_t end) : begin_addr(start), end_addr(end) {}
		bb_t(const bb_t&) = default;
		bb_t(bb_t&&) = default;
		~bb_t() = default;

		bool contains (addr_t addr){
			return begin_addr <= addr && addr <= end_addr;
		}

		size_t numInstrucitons(addr_t addr) const {
			return ins.size();
		}

		ins_t& operator[](size_t i) const {
			return ins[i];
		}
	};

	enum class status {
		empty,
		building,
		built,
		optimized,
		jited
	};

	template<class Ins_t, typename Isa_t>
	struct tracker_t {
		using ins_t = Ins_t;
		using isa_t = Isa_t;
		using bb_t = ast::bb::bb_t<Ins_t, Isa_t>;

		bb_t bb;
		status bb_status = status::empty;

		//TODO: add timestamps to track how hot/cold
		//this basic block is

		//TODO: JIT smart pointer for function pointers
		//for a future recompiler

		tracker_t() = default;
		tracker_t(addr_t start, addr_t end) : bb(start, end) {}
		tracker_t(const tracker_t&) = default;
		tracker_t(tracker_t&&) = default;
		~tracker_t() = default;

		bool contains(addr_t addr) {
			return bb.contains;
		}
	};

} //namespace ast

#endif //BASIC_BLOCK_H