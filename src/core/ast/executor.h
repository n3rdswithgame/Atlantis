#ifndef AST_EXECUTOR
#define AST_EXECUTOR

#include "core/targets.h"

#include "common/types.h"

namespace ast {
	template<class CRTP, emu_targets target>
	class Executor {
		#define crtp (static_cast<CRTP>(*this))

		using emu_traits = typename ast::emu_traits<target>;
		using cpu_t = typename emu_traits::cpu_t;
		using decoder_t = Decoder<target>;
		using dispatch_t = Dispatch<target>;
		using bb_t = typename dispatch_t::bb;

		cpu_t cpu;
		decoder_t decoder;
		dispatch_t dispatch;
		non_owning<bb_t> activeBB = nullptr;

	public:
		template<typename Mmu>
		Executor(Mmu* mmu) : cpu(), decoder(mmu) {
		}

		cpu_t& getCpu() {
			return cpu;
		}

		decoder_t& decoder() {
			return decoder;
		}

		void execOneIns() {
			addr_t addr = cpu.getExecAddr();
			updateBB(addr);
		}

	private:

		void updateBB(addr_t addr) {
			if(activeBB == nullptr || !(activeBB->contains(addr)))
				fetchBB(addr);
		}

		void fetchBB(addr_t addr) {
			activeBB = dispatch[addr];
		}

		#undef crtp
	};
}//namespace ast

#endif //AST_EXECUTOR