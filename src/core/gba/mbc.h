#ifndef MBC_H
#define MBC_H

namespace gba {

	enum class mbc_type {
		none,
	};

	template<typename Rom, typename Mmu> 
	class mbc {
		Rom* rom
		Mmu mmu;

	public:

		template<typename T>
		auto read(addr_t addr) -> decltype(mmu.read<T>(addr)) {
			return mmu.read<T>(addr);
		}

		template<typename T>
		auto write(addr_t addr) -> decltype(mmu.write<T>(addr)) {
			//TODO: implemnt cheats and onWrite hooks
			return mmu.write<T>(addr);
		}

	};
} //namespace mbc

#endif //MBC_H