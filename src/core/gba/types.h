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

		using tick_t	= std::chrono::duration<u64, std::ratio<1,16 * 1024 * 1024>>; 	//16.78 MHz

		using dot_t		= std::chrono::duration<u64, relative<tick_t, 4>>; 				//4 cycles per dot
		using line_t	= std::chrono::duration<u64, relative<dot_t, 308>>;				//308 dots per line(240 Hdraw + 68 Hblank)
		using frame_t	= std::chrono::duration<u64, relative<line_t, 228>>;			//228 lines per frame(160 Vdraw + 68 Vblank)


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