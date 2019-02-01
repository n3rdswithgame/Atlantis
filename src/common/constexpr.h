#ifndef CONSTEXPR_H
#define CONSTEXPR_H

#include <algorithm>

namespace cexpr {

	template< class T, class Compare >
	constexpr T max( std::initializer_list<T> ilist, Compare comp ) {
		std::max(ilist, comp);
	}

	//ripped from https://en.cppreference.com/w/cpp/algorithm/lower_bound and marked constexpr
	template<class ForwardIt, class T, class Compare>
	constexpr ForwardIt lower_bound(ForwardIt first, ForwardIt last, const T& value, Compare comp)
	{
		ForwardIt it;
		typename std::iterator_traits<ForwardIt>::difference_type count, step;
		count = std::distance(first, last);

		while (count > 0) {
			it = first;
			step = count / 2;
			std::advance(it, step);
			if (comp(*it, value)) {
				first = ++it;
				count -= step + 1;
			}
			else
				count = step;
		}
		return first;
	}

	//also ripped from https://en.cppreference.com/w/cpp/algorithm/lower_bound and marked constexpr
	template<class ForwardIt, class T, class Compare=std::less<>>
	constexpr ForwardIt binary_find(ForwardIt first, ForwardIt last, const T& value, Compare comp={})
	{
		first = std::lower_bound(first, last, value, comp);
		return first != last && !comp(value, *first) ? first : last;
	}
}

#endif