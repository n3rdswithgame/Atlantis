#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "ast.h"

#include <algorithm>
#include <chrono>
#include <unordered_map>

#include "common/logger.h"
#include "common/types.h"


namespace ast {
	template<emu_targets target>
	class dispatcher {
	public:
		using ins_t = typename emu_traits<target>::ins_t;
		using isa_t = typename emu_traits<target>::isa_t;


		using bb = typename bb::template basicblock_t<target>;
		using tracker = typename bb::template tracker_t<target>;
		
	private:
		using dispatcher_type = std::unordered_map<addr_t, tracker>;
		dispatcher_type dispatch;
		tracker dummy;//In the exceptional event that a tracker fails to alloc, retrun something that isn't dangling

	public:
		dispatcher() = default;

		tracker& get_tracker_raw(addr_t addr) {

			auto it = std::find_if(dispatch.begin(), dispatch.end(), [=](tracker t) {
				return t.contains(addr);
			});

			if (it != dispatch.end()) {
				return *it;
			}

			auto[inserted, succeded] =
				dispatch.emplace_back(std::piecewise_construct, {addr}, {addr, addr});

			if(!succeded) {
				FATAL("Unable to create basic block starting at {:08x}. using dummy", addr);
				return dummy;
			}

			return *inserted;
		}

		tracker& get_tracker(addr_t addr) {
			//using chrono::steady_clock;
			//static steady_clock::time_point t_zero = steady_clock::now();

			tracker& t = get_tracker_raw(addr);

			//TODO: timesamp stuff to track hot/cold codepaths

			return t;
		}

		bb& operator[](addr_t addr) {
			tracker& t = get_tracker(addr);
			return t.bb;
		}

		void invalidate(addr_t addr) {
			tracker& t = get_tracker_raw(addr);

			t.ins.erase(
				std::remove(t.ins.begin() + (addr - t.start), t.ins.end(),
					[](ins_t){return true;})
			);
			t.end = addr;
		}
	};
}

#endif //DISPATCHER_H