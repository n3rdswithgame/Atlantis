#ifndef MEM_H
#define MEM_H

#include <array>
#include <type_traits>
#include <string_view>
#include <tuple>

#include "common/types.h"
#include "common/unreachable.h"



namespace mem{

	template<typename T>
	constexpr size_t width_to_index() {
		if constexpr(std::is_same<T, u8>::value || std::is_same<T,s8>::value)
			return 0;
		else if constexpr(std::is_same<T,u16>::value || std::is_same<T,s16>::value)
			return 1;
		else if constexpr(std::is_same<T,u32>::value || std::is_same<T,s32>::value)
			return 2;
		else
			return UNREACHABLE(size_t);
	}

	struct region {
		std::string_view name;

		addr_t start;
		addr_t end;

		std::array<s64, 3> timings; // 0 = byte, 1 = hword, 2 = word

		ptr<u8> mem;

	};

	struct region_comparator {
		bool operator ()(region r, addr_t addr) {
			return r.start < addr;
		}

		bool operator ()(addr_t addr, region r) {
			return r.start < addr;
		}
	};

	
	enum class memop {
		read,
		write
	};

	template<typename T, memop op>
	struct memop_traits {};

	template<typename T>
	struct memop_traits<T, memop::read> {
		//T 	= read value
		//s64 	= number of cycles / -1 for invalid read
		using ret_val = std::tuple<T, s64>;
	};

	template<typename T>
	struct memop_traits<T, memop::write> {
		//s64	= number of cycles / -1 for invalid write
		using ret_val = std::tuple<s64>;
	};

	template<typename T>
	using read_ret  = typename memop_traits<T,memop::read>::ret_val;

	template<typename T>
	using write_ret = typename memop_traits<T,memop::write>::ret_val;

}

#define make_region(name, start, end, timing_byte, timing_hword, timing_word) ((::mem::region{name, start, end, {timing_byte, timing_hword, timing_word}, nullptr}))
#endif