#ifndef LIFTER_H
#define LIFTER_H

#include <algorithm>

#include "common/types.h"
#include "../mem.h"

namespace ast {
	template<class ins_t, typename isa_t, class CRTP, class mmu_t>
	class Lifter {
	#define crtp (static_cast<CRTP*>(this))
		mmu_t* mmu;

	public:
		Lifter(mmu_t* m) : mmu(m) {}
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
			return mmu->read(addr);
		}

	#undef crtp
	};
} //namespace ast

#endif //LIFTER_H