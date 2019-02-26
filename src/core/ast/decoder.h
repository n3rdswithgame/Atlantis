#ifndef AST_DECODER_H
#define AST_DECODER_H

#include <algorithm>

#include "common/types.h"
#include "core/ast/types.h"
#include "core/mem.h"

//"Concept":

namespace ast {

	template<class CRTP, emu_targets target>
	class Decoder {
	#define crtp (static_cast<CRTP*>(this))

		using emu_traits = typename ast::emu_traits<target>;
		typename emu_traits::mmu_t* mmu;



	public:
		
		using ins_t = typename emu_traits::ins_t;
		using isa_t = typename emu_traits::isa_t;
		using mmu_t = typename emu_traits::mmu_t;

		Decoder(mmu_t& m) : mmu(&m) {}
		Decoder(Decoder&& l) {
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

#endif //AST_DECODER_H