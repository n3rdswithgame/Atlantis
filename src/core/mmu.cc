#include "mmu.h"

#include "core/mem.h"

#include "common/constexpr.h"
#include "common/logger.h"

#include <optional>
#include <type_traits>
#include <tuple>
#include <variant>


namespace mmu {

std::array/*<mem::region>*/ memmap = 
	{
		//general internal memory
		make_region("bios"		, 0x0000'0000, 0x0000'3fff, 1,  1,  1),	
		make_region("ewram"		, 0x0200'0000, 0x0203'ffff, 3,  3,  6),	
		make_region("iwram"		, 0x0300'0000, 0x0300'7fff, 1,  1,  1),
		make_region("ioreg"		, 0x0400'0000, 0x0400'03fe, 1,  1,  1),

		//internal display memory
		make_region("palette"	, 0x0500'0000, 0x0500'03ff, 1,  1,  2),
		make_region("vram"      , 0x0600'0000, 0x0601'7fff, 1,  1,  2),
		make_region("oam"		, 0x0700'0000, 0x0700'03ff, 1,  1,  1),

		//external gamepak
		make_region("wait0"		, 0x0800'0000, 0x09ff'ffff, 5,  5,  8),
		make_region("wait1"		, 0x0a00'0000, 0x0bff'ffff, 5,  5,  8),
		make_region("wait2"		, 0x0c00'0000, 0x0dff'ffff, 5,  5,  8),
		make_region("sram"		, 0x0e00'0000, 0x0e00'ffff, 5, -1, -1),

	};

	constexpr std::optional<mem::region> addr_to_region(addr_t addr) {
		auto it = cexpr::binary_find(memmap.begin(), memmap.end(), addr, mem::region_comparator{});
		if(it != memmap.end())
			return *it;
		return std::nullopt;
	}


	template<typename T, mem::memop op>
	typename ::mem::memop_traits<T,op>::ret_val memory_operation(addr_t addr, T write_val=0) {
		//TODO check alignment of addr

		std::optional<mem::region> region_opt = addr_to_region(addr);
		typename ::mem::memop_traits<T,op>::ret_val ret;

		if(!region_opt) {
			//WARNING("Attempt to {} from unmapped address {:x}", op, addr);
			std::get<s64>(ret) = -1;
			return ret;
		}

		mem::region& region = *region_opt;

		ptr<u8> backing = region.mem;

		if constexpr(op == mem::memop::read) {
			//TODO: actually do the read
		} else {
			u8 tmp[sizeof(T)];
			for(int i = 0; i < sizeof(T); i++) {
				tmp[i] = write_val & 0xff;
				write_val = write_val >> 8;
			}
			addr_t off = addr - region.start;
			for(int i = 0; i < sizeof(T); i++) {
				backing[off + i] = tmp[i];
			}

		}
		
		const size_t indx = mem::width_to_index<T>();
		std::get<s64>(ret) = region.timings[indx];

		return ret;
		
	}

	template<typename T>
	mem::read_ret<T> read(addr_t addr) {
		return memory_operation<T, mem::memop::read>(addr);
	}

	template<typename T>
	mem::write_ret<T> write(addr_t addr, T t) {
		return memory_operation<T, mem::memop::write>(addr, t);
	}

	
} //namespace mmu