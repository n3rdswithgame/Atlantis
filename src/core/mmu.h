#ifndef MMU_H
#define MMU_H

#include "mem.h"

#include "common/singleton.h"
#include "common/types.h"

namespace mmu {

	bool init();
	void term();

	template<typename T>
	mem::read_ret<T> read(addr_t);

	template<typename T>
	mem::write_ret<T> write(addr_t, T);

	auto readU8  = read<u8>;
	auto readS8  = read<s8>;
	auto readU16 = read<u16>;
	auto readS16 = read<s16>;
	auto readU32 = read<u32>;
	auto readS32 = read<s32>;

	auto writeU8  = write<u8>;
	auto writeS8  = write<s8>;
	auto writeU16 = write<u16>;
	auto writeS16 = write<s16>;
	auto writeU32 = write<u32>;
	auto writeS32 = write<s32>;

	class mmu {
	public:
		template<typename T>
		mem::read_ret<T> read (addr_t addr) {return read<T>(addr);}
		
		template<typename T>
		mem::write_ret<T> write (addr_t addr, T val) {return writeU8 (addr, val);}
	};

} //namespace mmu

#endif