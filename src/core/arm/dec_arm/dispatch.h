#ifndef DEC_DISPATCH_H
#define DEC_DISPATCH_H


#include "status.h"

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
								arm::dec::status(addr_t, u32, out<::arm::ins_t>)
							 >;

		template<class Mask, decoder_func dec>
		struct decoder_impl {
			using mask = Mask;
			static status decode(addr_t addr, u32 ins, out<ins_t> i) {
				if(Mask::matches(ins))
					return dec(addr, ins, i);
				else
					return status::notchecked;
			}
		};


		template<typename Dec, typename... Decs>
		struct dispatch {
			static status impl(addr_t addr, u32 ins, out<ins_t> i) {
				status stat = Dec::decode(addr, ins, i);
				if(stat == status::notchecked || stat == status::future)
					return dispatch<Decs...>::impl(addr, ins, i);
				else
					return stat;
			}
		};

		//template recursion base case
		template<typename Dec>
		struct dispatch<Dec> {
			static status impl(addr_t addr, u32 ins, out<ins_t> i) {
				status stat = Dec::decode(addr, ins, i);
				if(stat == status::notchecked || stat == status::future)
					return status::nomatch; //no more to recurse so no match
				else
					return stat;
			}
		};

	} //namespace arm::dec::impl

	using impl::decoder_func;
	template<class Mask, decoder_func dec>
	using decoder = impl::decoder_impl<Mask, dec>;

	template<typename... Decs>
	inline status dispatch(addr_t addr, u32 ins, out<::arm::ins_t> i) {
		return impl::dispatch<Decs...>::impl(addr, ins, i);
	}

	namespace arm {
		template<class Mask, decoder_func dec>
		using decoder = ::arm::dec::decoder<Mask, dec>;

		template<typename... Decs>
		inline status dispatch(addr_t addr, u32 ins, out<::arm::ins_t> i) {
			return ::arm::dec::dispatch<Decs...>(addr, ins, i);
		}

	} //namespace arm::dec::arm

} //namespace arm::dec

#endif //DEC_DISPATCH_H