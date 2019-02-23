#ifndef GBA_TYPES_H
#define GBA_TYPES_H

#include "memmap.h"

#include "core/mmu.h"

#include "core/arm/arm.h"

#include "core/ast/types.h"

#include "common/types.h"

#include <chrono>
#include <ratio>

namespace ast {
	template<>
	struct emu_traits<emu_targets::GBA> : arm::emu_traits{
		template<typename base, std::intmax_t Num, std::intmax_t Denom = 1>
		using relative = std::ratio_multiply<typename base::period, std::ratio<Num, Denom>>;

		using region_t	= gba::mem::region;
		using mmu_t		= mmu::mmu<region_t>;

		//using BB_t	= ast::bb::bb_t<ins_t, isa>;
		//using BBT_t	= ast::bb::tracker_t<ins_t, isa>;


		static mem::map<region_t>& getMap() {
			return gba::mem::map;
		}
	};
} //namespace ast

namespace gba {
	using emu_traits = ast::emu_traits<emu_targets::GBA>;
} //namespace gba

#endif