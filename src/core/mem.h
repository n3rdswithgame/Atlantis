#ifndef MEM_H
#define MEM_H

#include <array>
#include <algorithm>
#include <type_traits>
#include <string_view>
#include <tuple>

#include "common/constexpr.h"
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

	enum class gba_region {
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

		count
	};

	struct region_t {
		addr_t start;
		addr_t end;

		std::array<s64, 3> timings; // 0 = byte, 1 = hword, 2 = word

		//TODO: replace dumb pointer with a complex 
		//backing type that knows when it is owning
		//and when it is just aliasing
		//OR: keep it so the mmu doesn't own the 
		//memory and can stay constexpr and let 
		//memory banker manage the memory
		non_owning_ptr<u8> mem;

		//TODO: on_write handler

	};



	template<typename Region>
	using memmap = std::array<region_t, static_cast<size_t>(Region::count)>;

	template<typename Region>
	struct comparator {
		bool operator ()(Region r, addr_t addr) {
			return r.start < addr;
		}

		bool operator ()(addr_t addr, Region r) {
			return addr < r.start;
		}
	};

#define BIT(n) (1 << n)
	enum class error {
		success = 0,
		unmapped = BIT(1),
		unaligned = BIT(2),
	};
#undef BIT

	constexpr error operator|(error e1, error e2) {
		return static_cast<error>(
			static_cast<std::underlying_type<error>::type>(e1) | 
			static_cast<std::underlying_type<error>::type>(e2)
		);
	}

	constexpr error operator|=(error& e1, error e2) {
		e1 = static_cast<error>(
			static_cast<std::underlying_type<error>::type>(e1) | 
			static_cast<std::underlying_type<error>::type>(e2)
		);
		return e1;
	}
	
	enum class memop {
		read,
		write
	};

	template<typename T, memop op>
	struct memop_traits {
		//one of these will fail during template instantiation
		static_assert(std::is_same<T, std::true_type>::value,  "invalid memop");
		static_assert(std::is_same<T, std::false_type>::value, "invalid memop");
	};

	template<typename T>
	struct memop_traits<T, memop::read> {
		//reg_t 	= read value
		//s64 		= number of cycles 
		//error 	= one of the above mem::errors
		struct ret_val {
			reg_t read_val = 0;
			s64 timing = 0;
			error status = error::success;
		};
	};

	template<typename T>
	struct memop_traits<T, memop::write> {
		//s64		= number of cycles / one of the above mem::errors
		//error 	= one of the above mem::errors
		struct ret_val {
			s64 timing = 0;
			error status = error::success;
		};
	};

	template<typename T>
	using read_ret  = typename memop_traits<T,memop::read>::ret_val;

	template<typename T>
	using write_ret = typename memop_traits<T,memop::write>::ret_val;

}//namespace mem

#define make_region(name, start, end, timing_byte, timing_hword, timing_word) 					\
	((::mem::region_t{start, end, {timing_byte, timing_hword, timing_word}, nullptr}))

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