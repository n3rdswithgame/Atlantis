#ifndef MASK_H
#define MASK_H

#include <cstddef>
#include <type_traits>
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

	//specalize it for the empty case just so I can create place holder masks for the dispathc
	//without having to figure out what the mask is
	//This empty speclization will match never (its not defined)
	template<>
	struct combine<> : mask<0,0> {};

	constexpr size_t get_bit(size_t bit, size_t pos) {
		return (bit & 1) << pos;
	}

	template<size_t b, size_t pos>
	struct bit : mask<get_bit(b,pos), get_bit(~b, pos)> {
		constexpr static bool extract(size_t val) {
			constexpr const mask<get_bit(b,pos), get_bit(~b, pos)> ma;
			return (val & ma.m) == ma.m;
		}

		constexpr static bool test(size_t val) {
			return extract(val);
		}
	};

	constexpr size_t get_lower(size_t n) {
		return static_cast<size_t>((1 << n) - 1);
	}

	template<size_t n>
	struct lower : mask<get_lower(n), 0> {
		constexpr static size_t extract(size_t v) {
			return v & get_lower(n);
		}
	};

	//end then begin as all of the arm docs show high bits on the left and low bits on right
	//takes bits (high-low)...0 and maps them to high...low
	constexpr size_t get_bit_range(size_t range, size_t high, size_t low) {
		size_t mask = get_lower(high-low + 1);
		return (range & mask ) << low;
	}

	template<size_t m, size_t inv_m, size_t end, size_t begin>
	struct raw_bit_range : mask<get_bit_range(m, end, begin), get_bit_range(inv_m, end, begin)> {
		constexpr static size_t extract(size_t v) {
			return strip(v) >> begin;
		}
		constexpr static size_t strip(size_t v) {
			constexpr const mask<get_bit_range(m, end, begin), get_bit_range(inv_m, end, begin)> msk;
			return (v & (msk.m | msk.inv_m));	
		}
	};

	template<size_t val, size_t end, size_t begin>
	struct bit_range : raw_bit_range<val, ~val, end, begin> {};

	template<typename Mask, size_t end, size_t begin>
	struct shift_mask : raw_bit_range<Mask::m, Mask::inv_m, end, begin> {};

	template<size_t end, size_t begin>
	struct range : bit_range<0, end, begin> { 
	//use a mask of 0, as the inv_m will be all 1s so there
	//will be only 1s in the relovant positions for extract
		using bit_range<0, end, begin>::extract;
	};

	//should be zero
	template<size_t end, size_t begin>
	struct sbz : bit_range<0, end, begin> {};

	//should be one
	template<size_t end, size_t begin>
	struct sbo : bit_range<~(0ull), end, begin> {};

	//negation, 'not' is a reserved keyword and I want to keep with all of these being lowercase
	template<typename Mask>
	struct negation : Mask {
		constexpr static bool matches(size_t candidate) {
			return !(Mask::matches(candidate));
		}
	};

	//disjunctions, `or` is a reserved keyword and I want to keep with all of these being lowercase
	template<typename... Masks>
	struct disjunction : Masks... {
		constexpr static bool matches(size_t candidate) {
			return (Masks::matches(candidate) || ...);
		}
	};

	//conjunctions, `and` is a reserved keyword and I want to keep with all of these being lowercase
	//very similary to combine, except combine will will build just one mask while conjunction will
	//call the matches function, which allows it to interop with disjunction and negation
	template<typename... Masks>
	struct conjunction : Masks... {
		constexpr static bool matches(size_t candidate) {
			return (Masks::matches(candidate) && ...);
		}
	};

} //namespace mask
template<char c>
constexpr size_t buildMask(const char* str, size_t size) {
	size_t m = 0;
	for(size_t i = 0; i < size; i++) {
		m <<= 1;
		if(str[i] == c)
			m |= 1;
	}
	return m;
}
constexpr size_t operator""_msk0(const char* str, size_t size) {
	return buildMask<'0'>(str, size);
}
constexpr size_t operator""_msk1(const char* str, size_t size) {
	return buildMask<'1'>(str, size);
}


#define MSK(str) 	::bit::mask::mask<str ## _msk0, str ## _msk1>

#endif //MASK_H