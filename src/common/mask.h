#ifndef MASK_H
#define MASK_H

#include <cstddef>
#include <utility>

namespace mask {
	template<size_t mask_T, size_t inv_mask_T>
		struct mask {
			constexpr static size_t m = mask_T;				//To mask desired 1s
			constexpr static size_t inv_m = inv_mask_T;		//to mask desired 0s

			constexpr static bool matches(size_t candidate) {
				if((candidate & m) != m)				// are 1s in the right place for the candidate
					return false;
				if((~candidate & inv_m) != inv_m)		// are 0s in the right place for the candidate
					return false;
				return true;
			}

			constexpr static auto make_pair() -> std::pair<size_t, size_t> {
				return std::make_pair(m, inv_m);
			}
		};

		//This is implemnted using bitwise |, however as a mask it neds to
		//pass both the lhs *&* the rhs, so its operator & for the masks
		template<typename... Args>
		constexpr size_t combine_helper (Args... args) {
			return (args|...);
		}

		template<typename... masks>
		struct combine : mask<combine_helper(masks::m...), combine_helper(masks::inv_m...)> {};

		constexpr size_t get_bit(size_t bit, size_t pos) {
			return (bit & 1) << pos;
		}

		template<size_t b, size_t pos>
		struct bit : mask<get_bit(b,pos), get_bit(~b, pos)> {};

		//end then begin as all of the arm docs show high bits on the left and low bits on right
		//takes bits (high-low)...0 and maps them to high...low
		constexpr size_t get_bit_range(size_t range, size_t high, size_t low) {
			size_t mask = static_cast<size_t>(( 1<<(high-low + 1) )-1);
			return (range & mask ) << low;
		}

		template<size_t val, size_t end, size_t begin>
		struct bit_range : mask<get_bit_range(val, end, begin), get_bit_range(~val, end, begin)> {};


} //namespace mask

#endif //MASK_H