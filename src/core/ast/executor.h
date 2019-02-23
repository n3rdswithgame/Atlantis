#ifndef AST_EXECUTOR
#define AST_EXECUTOR

#include "core/targets.h"

namespace ast {
	template<class CRTP, emu_targets target>
	class Executor {
		#define crtp (static_cast<CRTP>(*this))

		using emu_traits = typename ast::emu_traits<target>;
		using cpu_t = typename emu_traits::cpu_t;
		using lifter_t = Lifter<target>;

		cpu_t cpu;
		Lifter<target> lifter;

		template<typename Mmu>
		Executor(Mmu* mmu) : cpu(), lifter(mmu) {
		}

		cpu_t& getCpu() {
			return cpu;
		}

		lifter_t& lifter() {
			return lifter;
		}

		

		#undef crtp
	};
}//namespace ast

#endif //AST_EXECUTOR