#include "mmu.h"

#include "common/constexpr.h"
#include "common/logger.h"

#include "core/mem.h"

#include <algorithm>
#include <optional>
#include <type_traits>
#include <tuple>
#include <variant>


namespace mmu {

std::array/*<mem::region_t>*/ memmap = 
	{
		//general internal memory
		make_region(mem::region::bios		, 0x0000'0000, 0x0000'3fff, 1,  1,  1),	
		make_region(mem::region::ewram		, 0x0200'0000, 0x0203'ffff, 3,  3,  6),	
		make_region(mem::region::iwram		, 0x0300'0000, 0x0300'7fff, 1,  1,  1),
		make_region(mem::region::ioreg		, 0x0400'0000, 0x0400'03fe, 1,  1,  1),

		//internal display memory
		make_region(mem::region::palette	, 0x0500'0000, 0x0500'03ff, 1,  1,  2),
		make_region(mem::region::vram      	, 0x0600'0000, 0x0601'7fff, 1,  1,  2),
		make_region(mem::region::oam		, 0x0700'0000, 0x0700'03ff, 1,  1,  1),

		//external gamepak
		make_region(mem::region::wait0		, 0x0800'0000, 0x09ff'ffff, 5,  5,  8),
		make_region(mem::region::wait1		, 0x0a00'0000, 0x0bff'ffff, 5,  5,  8),
		make_region(mem::region::wait2		, 0x0c00'0000, 0x0dff'ffff, 5,  5,  8),
		make_region(mem::region::sram		, 0x0e00'0000, 0x0e00'ffff, 5, -1, -1),

	};

	bool init() {
		auto first_fail = std::find_if_not(memmap.begin(), memmap.end(), [](mem::region_t& region) {
			region.mem = new(std::nothrow) u8[region.end - region.start];
			if(region.mem == nullptr)
				return false;
			else
				return true;
		});

		if(first_fail == memmap.end())
			return true;

		std::for_each(memmap.begin(), first_fail, [](mem::region_t& region) {
			delete [] std::exchange(region.mem, nullptr);
		});

		return false;
	}

	void term() {
		std::for_each(memmap.begin(), memmap.end(), [](mem::region_t& region) {
			delete [] std::exchange(region.mem, nullptr);
		});
	}

	constexpr std::optional<mem::region_t> addr_to_region(addr_t addr) {
		auto it = cexpr::binary_find(memmap.begin(), memmap.end(), addr, mem::region_t_comparator{});
		if(it != memmap.end())
			return *it;
		return std::nullopt;
	}


	template<typename T>
	constexpr bool check_alignment(addr_t addr) {
		//an algned value is one whose alignment mask is 0
		//with alignment mask being: 
		//0b0 for byte, 0b1 for hword, 0b11 for word
		if( addr_t alignment_mask = sizeof(T) - 1; //if-init for making the mask
			addr & alignment_mask) 
			return true;
		else
			return false;
	}

	template<typename T>
	constexpr reg_t extend(T t) {
		//TODO: implement
		return static_cast<reg_t>(t);
	}

	template<typename T, mem::memop op>
	typename ::mem::memop_traits<T,op>::ret_val memory_operation(addr_t addr, T write_val=0) {
		typename ::mem::memop_traits<T,op>::ret_val ret;

		if(check_alignment<T>(addr)) { //
			WARNING("Attempt to {} {}-byte val from unaligned address {:x}", op, sizeof(T), addr);
			ret.timing = mem::error::unaligned;
			return ret;
		}

		std::optional<mem::region_t> region_opt = addr_to_region(addr);

		if(!region_opt) {
			WARNING("Attempt to {} from unmapped address {:x}", op, addr);
			ret.timing = mem::error::unmapped;
			return ret;
		}

		mem::region_t& region = *region_opt;

		ptr<u8> backing = region.mem;
		addr_t off = addr - region.start;

		if constexpr(op == mem::memop::read) {
			//reusing write_val as a temporary to use an otherwise 
			//unused paramater and silence the warning
			write_val = 0; //probalby 0 anyway but just ensuring
			for(addr_t i = sizeof(T) - 1; i >= 0 ; i--) {
				write_val |= static_cast<T>(static_cast<reg_t>(backing[off + i]) << (8*i)); 
			}
			ret.read_val = extend<T>(write_val);
			return ret;
		} else {
			u8 tmp[sizeof(T)];
			for(addr_t i = 0; i < sizeof(T); i++) {
				tmp[i] = static_cast<u8>(write_val & 0xff);
				write_val = static_cast<T>(write_val >> 8);
			}
			for(addr_t i = 0; i < sizeof(T); i++) {
				backing[off + i] = tmp[i];
			}

		}
		
		const size_t indx = mem::width_to_index<T>();
		ret.timing = region.timings[indx];

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