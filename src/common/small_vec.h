#ifndef COMMON_SMALL_VEC_H
#define COMMON_SMALL_VEC_H

#include "common/constexpr.h"

#include <array>
#include <type_traits>

//TODO: before using, either finish implementing the full vector api,
//or use std::vector with a custom alloctor

namespace common {

	template<typename T, size_t N>
	class small_vector{
		std::array<T, N> vec = {};
		size_t empty = 0;
	public:
		constexpr small_vector() noexcept(std::is_nothrow_default_constructible_v<T>) = default;
		
		constexpr small_vector(small_vector& v) noexcept(std::is_nothrow_copy_constructible_v<T>) {
			operator=(v);
		}

		small_vector<T,N>& operator=(small_vector& v) {
			empty = v.empty;
			cexpr::copy(v.begin(), v.end(), begin());
			return *this;
		}
		
		constexpr small_vector(small_vector&& v) noexcept(std::is_nothrow_move_constructible_v<T>) {
			operator=(v);
		}

		small_vector<T,N>& operator=(small_vector&& v) {
			empty = std::move(v.empty);
			cexpr::move(v.begin(), v.end(), begin());
			return *this;
		}

		~small_vector() = default;

		T& operator[](size_t i) {
			return vec[i];
		}

		T& at(size_t i) {
			return vec.at(i);
		}

		auto begin() const -> decltype(vec.begin()){
			return vec.begin();
		}

		auto end() const -> decltype(vec.begin() + 1){
			return vec.begin() + empty;
		}

		auto hardEnd() const -> decltype(vec.end()){
			return vec.end();
		}

		size_t size() const {
			return empty;
		}

		size_t capacity() const {
			return N;
		}

		bool push_back(T& t) {
			if(size() == capacity())
				return false;
			vec[empty++] = t;
			return true;
		}

	};

}//namespace common

#endif // COMMON_SMALL_VEC_H