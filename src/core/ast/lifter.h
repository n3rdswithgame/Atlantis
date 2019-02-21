#ifndef LIFTER_H
#define LIFTER_H

#include <algorithm>

#include "common/types.h"
#include "core/mem.h"


//"Concept":

namespace ast {
	template<class CRTP, class ins_type, typename isa_type, class mmu_type>
	class Lifter {
	#define crtp (static_cast<CRTP*>(this))
		mmu_type* mmu;



	public:
		
		using ins_t = ins_type;
		using isa_t = isa_type;
		using mmu_t = mmu_type;

		Lifter(mmu_t& m) : mmu(&m) {}
		Lifter(Lifter&& l) {
			mmu = std::exchange(l.mmu, nullptr);
		}

		bool isValid() {
			return (mmu != nullptr);
		}

		ins_t fetch(addr_t addr) {
			return crtp->fetch_impl(addr);
		}
	protected:
		template<typename T>
		auto mmuFetch(addr_t addr) -> mem::read_ret<T>{
			return mmu->template read<T>(addr);
		}

	#undef crtp
	};
} //namespace ast

#endif //LIFTER_H