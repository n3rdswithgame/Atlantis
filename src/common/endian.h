#ifndef ENDIAN_H
#define ENDIAN_H

#include "types.h"

#include <type_traits>


namespace endian {

	template<typename T, typename U>
	inline constexpr bool same = std::is_same<T, U>::value;

	template<typename T>
	inline constexpr bool is_un = std::is_unsigned<T>::value;
		
	template<typename T>
	using make_un = typename std::make_unsigned<T>::type;

	struct little{};
	struct big{};

	#ifdef IS_LITTLE_ENDIAN
		using naitive = little;
	#else
		using naitive = big;
	#endif

	//inline std::integral_constant<bool, std::is_same_v<isLittle(), endian::little>>
	//	is_little;
	//inline std::integral_constant<bool, std::is_same_v<isLittle(), endian::big>>
	//	is_big;

	namespace impl{
		template<typename T> constexpr T swap(T);

		//macro to grab the nth lowest byte, shift it to the lowest
		//byte, mask away any leftover high bytes / garbage
		//and the static cast it to a byte
		#define BYTE(v, i)	(static_cast<u8>((v >> (8*i)) & 0xff))
		template<> constexpr u8 swap(u8 val) {
			return val;
		}

		template<> constexpr u16 swap(u16 val) {
			return BYTE(val, 0) | BYTE(val, 1);
		}

		template<> constexpr u32 swap(u32 val) {
			return BYTE(val, 0) | BYTE(val, 1) 
				| BYTE(val, 2) | BYTE(val, 3);
		}

		template<> constexpr u64 swap(u64 val) {
			return BYTE(val, 0) | BYTE(val, 1) 
				| BYTE(val, 2) | BYTE(val, 3)
				| BYTE(val, 4) | BYTE(val, 5) 
				| BYTE(val, 6) | BYTE(val, 7);
		}
		#undef BYTE
	}

	template<typename T, typename Endian>
	constexpr T swap(T t) {		
		if constexpr(same<naitive, Endian>) {
			return t;
		} else if constexpr(is_un<T>){
			return impl::swap<T>(t);
		} else {
			//temporarily remove the sign and call the unsigned 
			//overload to avoid issues with bitshifting singed
			//values that might inhibit the wanted optimizations

			//all of this on one line is just ugly
			make_un<T> un_t = static_cast<make_un<T>>(t);
			make_un<T> ret = impl::swap(un_t);
			return static_cast<T>(ret);
		}
	}

	template<typename T, typename from, typename to>
	constexpr T swap(T t) {
		if constexpr(same<from, to>) {
			return t;
		} else if constexpr(same<naitive, from>) {
			return swap<T, to>(t);
		} else {
			return swap<T, from>(t);
		}
	}
}// namespace endian

#endif //ENDIAN_Hs