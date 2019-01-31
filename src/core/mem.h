#ifndef MEM_H
#define MEM_H

#include <array>
#include <type_traits>
#include <string_view>
#include <tuple>

#include "common/types.h"
#include "common/unreachable.h"

#include <fmt/format.h>


namespace mem{

	template<typename T>
	constexpr size_t width_to_index() {
		//using std::is_same instead of sizeof
		//to prevent the accidental usage of a
		//struct instead of an integral type
		if constexpr(std::is_same<T, u8>::value || std::is_same<T,s8>::value)
			return 0;
		else if constexpr(std::is_same<T,u16>::value || std::is_same<T,s16>::value)
			return 1;
		else if constexpr(std::is_same<T,u32>::value || std::is_same<T,s32>::value)
			return 2;
		else
			return UNREACHABLE(size_t);
	}

	enum class region {
		bios,
		ewram,
		iwram,
		ioreg,
		palette,
		vram,
		oam,
		wait0,
		wait1,
		wait2,
		sram,
	};

	struct region_t {
		region reg;

		addr_t start;
		addr_t end;

		std::array<s64, 3> timings; // 0 = byte, 1 = hword, 2 = word

		//TODO: replace dumb pointer with a complex 
		//backing type that knows when it is owning
		//and when it is just aliasing
		ptr<u8> mem;

		//TODO: on_write handler

	};

	struct region_t_comparator {
		bool operator ()(region_t r, addr_t addr) {
			return r.start < addr;
		}

		bool operator ()(addr_t addr, region_t r) {
			return addr < r.start;
		}
	};

	enum error : s64 {
		unmapped = -1,
		unaligned = -2,
	};
	
	enum class memop {
		read,
		write
	};

	template<typename T, memop op>
	struct memop_traits {
		//one of these will fail during template instantiation
		static_assert(std::is_same<T, std::false_type>::value, "invalid memop");
		static_assert(std::is_same<T, std::true_type>::value,  "invalid memop");
	};

	template<typename T>
	struct memop_traits<T, memop::read> {
		//reg_t 	= read value
		//s64 		= number of cycles / one of the above mem::errors
		struct ret_val {
			reg_t read_val;
			s64 timing;
		};
	};

	template<typename T>
	struct memop_traits<T, memop::write> {
		//s64		= number of cycles / one of the above mem::errors
		struct ret_val {
			s64 timing;
		};
	};

	template<typename T>
	using read_ret  = typename memop_traits<T,memop::read>::ret_val;

	template<typename T>
	using write_ret = typename memop_traits<T,memop::write>::ret_val;

}//namespace mem

#define make_region(name, start, end, timing_byte, timing_hword, timing_word) ((::mem::region_t{name, start, end, {timing_byte, timing_hword, timing_word}, nullptr}))

namespace fmt{
	template<>
	struct formatter<mem::memop> {
		template <typename ParseContext>
		constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

		template <typename FormatContext>
		auto format(const mem::memop &op, FormatContext &ctx) {
			switch(op) {
			case mem::memop::read:
				return format_to(ctx.begin(), "memop::read");

			case mem::memop::write:
				return format_to(ctx.begin(), "memop::write");
			}
			return UNREACHABLE(decltype(format_to(ctx.begin(), "")));	
		}
	};
}//namespace fmt

#endif