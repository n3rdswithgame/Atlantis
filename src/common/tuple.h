#ifndef TUPLE_ALG_H
#define TUPLE_ALG_H

#include <tuple>
#include <utility>

namespace tuple::algo {

	

	template<typename Callable, typename First, typename... Args>
	bool any_of_impl(Callable f, First first, Args... args);

	template<typename Callable, typename... Args>
	bool any_of(Callable f, std::tuple<Args...> tuple) {
		return std::apply([&](auto... args) {
			find_if_impl(f, args...);
		}, tuple);
	}


	template<typename Callable, typename... Args, size_t... I>
	void for_each_impl(Callable, std::tuple<Args...>, std::index_sequence<I...>);

	template<typename Callable, typename... Args>
	void for_each(Callable f, std::tuple<Args...> tuple) {
		for_each_impl(f, tuple, std::make_index_sequence<sizeof...(Args)>{});
	}


	//-------------------------------impl-------------------------------


	//TODO: try and think of a way of doing this without template
	//recursion and with the early bail out if even possible

	template<typename Callable, typename First>
	bool any_of_impl(Callable f, First first) {
		if( f(first)) {
			return true;
		} else {
			return false;
		}
	}

	template<typename Callable, typename First, typename... Args>
	bool any_of_impl(Callable f, First first, Args... args) {
		if( f(first)) {
			return true;
		} else {
			return find_if_impl(f, args...);
		}
	}

	template<typename Callable, typename... Args, size_t... I>
	void for_each_impl(Callable f, std::tuple<Args...> tuple, std::index_sequence<I...> ) {
		//have to assing to a variable for some dumb reason inorder to expand the pack
		auto tmp = {(f(std::get<I>(tuple)), 0)...};
		static_cast<void>(tmp); //to silence the unused variable warning
	}
}

#endif //TUPLE_ALG_H