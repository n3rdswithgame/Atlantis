#ifndef MASK_H
#define MASK_H

#include <cstddef>
#include <utility>

namespace bit::mask {
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

			constexpr static size_t apply(size_t val) {
				return m & val;
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

		//specalize it for the one entry case to prevent a fallback into the variadic case aboce
		//for hopefully better compiler speed, but also to preserve special properties that might be 
		//in that one type, like the extract function for bit/bit_range/lower
		template<typename mask>
		struct combine<mask> : mask {};

		constexpr size_t get_bit(size_t bit, size_t pos) {
			return (bit & 1) << pos;
		}

		template<size_t b, size_t pos>
		struct bit : mask<get_bit(b,pos), get_bit(~b, pos)> {
			constexpr static bool extract(size_t val) {
				constexpr const mask<get_bit(b,pos), get_bit(~b, pos)> m;
				return (val & m.m) == m.m;
			}
		};

		constexpr size_t get_lower(size_t n) {
			return static_cast<size_t>((1 << n) - 1);
		}

		template<size_t n>
		struct lower : mask<get_lower(n), 0> {};

		//end then begin as all of the arm docs show high bits on the left and low bits on right
		//takes bits (high-low)...0 and maps them to high...low
		constexpr size_t get_bit_range(size_t range, size_t high, size_t low) {
			size_t mask = get_lower(high-low + 1);
			return (range & mask ) << low;
		}

		template<size_t val, size_t end, size_t begin>
		struct bit_range : mask<get_bit_range(val, end, begin), get_bit_range(~val, end, begin)> {
			constexpr static size_t extract(size_t v) {
				constexpr const mask<get_bit_range(val, end, begin), get_bit_range(~val, end, begin)> m;
				return (v & (m.m | m.inv_m)) >> begin;
			}
		};




} //namespace mask

#endif //MASK_H