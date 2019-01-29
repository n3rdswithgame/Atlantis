#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "ast.h"

#include <chrono>
#include <map>

#include "common/types.h"

namespace ast {
	template<class T, typename isa_t>
	class dispatcher<T> {
		using bb = basic_block<T, isa_t>;
		using tracker = basic_block_tracker<T, isa_t>;

		using dispatcher_type = std::unordered_map<addr_t, tracker>;


		dispatcher_type dispatch;

	public:
		dispatcher() = default;

		tracker& get_tracker_by_start_raw(addr_t addr) {
			return dispatch[addr];
		}

		tracker& get_tracker_by_start(addr_t addr) {
			//using chrono::steady_clock;
			//static steady_clock::time_point t_zero = steady_clock::now();

			tracker& t = get_tracker_by_start_raw;

			//TODO: timesamp stuff to track hot/cold codepaths

			return t.bb;
		}

		bb& operator[](addr_t addr) {
			tracker& t = get_tracker_by_start(addr);
			return t.bb;
		}
	};
}

#endif //DISPATCHER_H