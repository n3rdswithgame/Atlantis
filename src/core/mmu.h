#ifndef MMU_H
#define MMU_H

#include "mem.h"

#include <array>
#include <optional>


#include "common/constexpr.h"
#include "common/endian.h"
#include "common/logger.h"
#include "common/singleton.h"
#include "common/types.h"

namespace mmu {

	//bool init();
	//void term();

	//template<typename T>
	//mem::read_ret<T> read(addr_t);

	//template<typename T>
	//mem::write_ret<T> write(addr_t, T);

	//auto readU8  = read<u8>;
	//auto readS8  = read<s8>;
	//auto readU16 = read<u16>;
	//auto readS16 = read<s16>;
	//auto readU32 = read<u32>;
	//auto readS32 = read<s32>;

	//auto writeU8  = write<u8>;
	//auto writeS8  = write<s8>;
	//auto writeU16 = write<u16>;
	//auto writeS16 = write<s16>;
	//auto writeU32 = write<u32>;
	//auto writeS32 = write<s32>;

	template<typename Region>
	class mmu {

		mem::map<Region> memmap;

	public:

		constexpr mmu(mem::map<Region>& m) {
			cexpr::copy(std::begin(m), std::end(m), std::begin(memmap));
		}

		template<typename T>
		constexpr auto read (addr_t addr) -> typename mem::read_ret<T> {
			return memop_impl<T, mem::memop::read>(addr);
		}
		
		template<typename T>
		constexpr auto write (addr_t addr, T val) -> typename mem::write_ret<T> {
			return memop_impl<T, mem::memop::write>(addr, val);
		}

		constexpr mem::region_t& operator[](Region r) {
			return memmap[static_cast<size_t>(r)];
		}

		constexpr const mem::region_t& operator[](Region r) const {
			return memmap[static_cast<size_t>(r)];
		}
	private:
		template<typename T, mem::memop op>
		constexpr auto memop_impl(addr_t addr, T write_val=0)
			-> typename ::mem::memop_traits<T,op>::ret_val
		{
			typename ::mem::memop_traits<T,op>::ret_val ret;
			ret.status = mem::error::success;
			constexpr bool isRead = op == mem::memop::read;

			//TODO: allow for unaligned access at this level and let a higher level keep / discard
			//the unalighed access
			if(check_alignment<T>(addr)) { //
				WARNING("Attempt to {} {}-byte val from unaligned address {:x}", op, sizeof(T), addr);
				ret.status |= mem::error::unaligned;
				return ret;
			}
			
			std::optional<mem::region_t> region_opt = addr_to_region(addr);

			if(!region_opt) {
				WARNING("Attempt to {} {} unmapped address {:x}", op, isRead ? "from" : "to" , addr);
				ret.status |= mem::error::unmapped;
				return ret;
			}
	
			mem::region_t& region = *region_opt;
	
			ptr<u8> backing = region.mem;
			addr_t off = addr - region.start;
	
			if constexpr(isRead) {
				//reusing write_val as a temporary to use an otherwise 
				//unused paramater and silence the warning
				write_val = 0; //probalby 0 anyway but just ensuring
				for(addr_t i = 0; i < sizeof(T) ; i++) {
					write_val |= static_cast<T>(static_cast<reg_t>(backing[off + i]) << (8*i)); 
				}
				ret.read_val = extend<T>(write_val);
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

		constexpr std::optional<mem::region_t> addr_to_region(addr_t addr) {
			auto contains_addr = [addr](mem::region_t r) {
				return cexpr::clamp(addr, r.start, r.end) == addr;
			};
			auto it = cexpr::find_if(memmap.begin(), memmap.end(), contains_addr);
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
	};

} //namespace mmu

#endif