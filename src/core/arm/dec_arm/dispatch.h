#ifndef DEC_DISPATCH_H
#define DEC_DISPATCH_H


#include "status.h"

#include <functional>
#include <type_traits>

#include "core/arm/arm.h"

#include "common/types.h"
#include "common/bit/mask.h"
#include "common/logger.h"

//TODO: see if I can rewrite dispatcher without the template bloat of
//variadic template recursion to check each one.

namespace arm::dec {
	namespace impl {
		using arm::dec::status;
		using decoder_func = std::add_pointer_t<
								arm::dec::status(addr_t, u32, out<arm::ins_t>)
							 >;

		template<class Mask, decoder_func dec>
		struct decoder_impl {
			using mask = Mask;
			inline static status decode(addr_t addr, u32 ins, out<ins_t> i) {
				if(Mask::matches(ins))
					return std::invoke(dec, addr, ins, i);
				else
					return status::notchecked;
			}
		};


		template<typename Dec, typename... Decs>
		struct dispatch {
			inline static status impl(addr_t addr, u32 ins, out<ins_t> i) {
				status stat = Dec::decode(addr, ins, i);
				if(stat == status::notchecked || stat == status::nomatch)
					return dispatch<Decs...>::impl(addr, ins, i);
				else if (stat == status::discard_current_dispatch)
					return status::nomatch;
				else
					return stat;
			}
		};

		//template recursion base case
		template<typename Dec>
		struct dispatch<Dec> {
			inline static status impl(addr_t addr, u32 ins, out<ins_t> i) {
				status stat = Dec::decode(addr, ins, i);
				if(stat == status::discard_current_dispatch)
					return status::nomatch;
				else
					return stat;
			}
		};

	} //namespace arm::dec::impl

	using impl::decoder_func;
	template<class Mask, decoder_func dec>
	using decoder = impl::decoder_impl<Mask, dec>;

	struct always : bit::mask::mask<0,0> {}; //always match for the decoder
	struct never : bit::mask::mask<1,1> {}; //never match for the decoder (low bit is either 0 or 1, not both)

	template<typename... Decs>
	inline status dispatch(addr_t addr, u32 ins, out<arm::ins_t> i) {
		return impl::dispatch<Decs...>::impl(addr, ins, i);
	}

	namespace a {
		template<class Mask, decoder_func dec>
		using decoder = arm::dec::decoder<Mask, dec>;

		template<typename... Decs>
		inline status dispatch(addr_t addr, u32 ins, out<arm::ins_t> i) {
			return arm::dec::dispatch<Decs...>(addr, ins, i);
		}

	} //namespace arm::dec::a


	//special functions that will return the status literals
	inline status IllFormed(addr_t, u32, out<arm::ins_t>) {
		return status::illformed;
	}

	inline status Discard(addr_t, u32, out<arm::ins_t>) {
		return status::discard_current_dispatch;
	}

	inline status NoMatch(addr_t, u32, out<arm::ins_t>) {
		return status::nomatch;
	}

	inline status Future(addr_t, u32, out<arm::ins_t>) {
		return status::future;
	}

} //namespace arm::dec

#endif //DEC_DISPATCH_H