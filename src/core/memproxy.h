#ifndef MBC_H
#define MBC_H

namespace mem {

	//mem::proxy handles will handle both memory banking and cheats. Both MiM memory access,
	//so mem::proxy will MiM any read (cheats) / write (mbc)

	//Concept
	template<typename CRTP, typename Rom, typename Mmu, typename Banking_E>
	class Proxy {
		#define crtp (static_cast<CRTP>(*this))

		Rom* rom;
		Mmu mmu;
		Banking_E mbc_type = Banking_E::none;

	public:

		using rom_t = Rom;
		using mmu_t = Mmu;

		Proxy(Rom& r) {
			rom = &r;
			crtp->initMMU();
		}

		~Proxy() = default;

		Mmu& getMmu() const {
			return mmu;
		}

		template<typename T>
		auto read(addr_t addr) -> decltype(mmu.template read<T>(addr)) {
			return mmu.template read<T>(addr);
		}

		template<typename T>
		auto write(addr_t addr) -> decltype(mmu.template write<T>(addr)) {
			//TODO: implemnt cheats and onWrite hooks
			return mmu.template write<T>(addr);
		}

	protected:
		Banking_E getMbcType() const {
			return mbc_type;
		}

		void setMbcType(Banking_E e) const {
			mbc_type = e;
		}

		#undef crtp
	};
} //namespace mbc

#endif //MBC_H