#include "mmu.h"

#include "common/constexpr.h"
#include "common/logger.h"

#include "core/mem.h"

#include <algorithm>
#include <type_traits>
#include <tuple>
#include <variant>


namespace mmu {

//	std::array/*<mem::region_t>*/ memmap = 
//	
//	{
//		//general internal memory
//		make_region(mem::region::bios		, 0x0000'0000, 0x0000'3fff, 1,  1,  1),	
//		make_region(mem::region::ewram		, 0x0200'0000, 0x0203'ffff, 3,  3,  6),	
//		make_region(mem::region::iwram		, 0x0300'0000, 0x0300'7fff, 1,  1,  1),
//		make_region(mem::region::ioreg		, 0x0400'0000, 0x0400'03fe, 1,  1,  1),
//
//		//internal display memory
//		make_region(mem::region::palette	, 0x0500'0000, 0x0500'03ff, 1,  1,  2),
//		make_region(mem::region::vram      	, 0x0600'0000, 0x0601'7fff, 1,  1,  2),
//		make_region(mem::region::oam		, 0x0700'0000, 0x0700'03ff, 1,  1,  1),
//
//		//external gamepak
//		make_region(mem::region::wait0		, 0x0800'0000, 0x09ff'ffff, 5,  5,  8),
//		make_region(mem::region::wait1		, 0x0a00'0000, 0x0bff'ffff, 5,  5,  8),
//		make_region(mem::region::wait2		, 0x0c00'0000, 0x0dff'ffff, 5,  5,  8),
//		make_region(mem::region::sram		, 0x0e00'0000, 0x0e00'ffff, 5, -1, -1),
//
//	};
//
//	bool init() {
//		auto first_fail = std::find_if_not(memmap.begin(), memmap.end(), [](mem::region_t& region) {
//			region.mem = new(std::nothrow) u8[region.end - region.start];
//			if(region.mem == nullptr)
//				return false;
//			else
//				return true;
//		});
//
//		if(first_fail == memmap.end())
//			return true;
//
//		std::for_each(memmap.begin(), first_fail, [](mem::region_t& region) {
//			delete [] std::exchange(region.mem, nullptr);
//		});
//
//		return false;
//	}
//
//	void term() {
//		std::for_each(memmap.begin(), memmap.end(), [](mem::region_t& region) {
//			delete [] std::exchange(region.mem, nullptr);
//		});
//	}
		
} //namespace mmu