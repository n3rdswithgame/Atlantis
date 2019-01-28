#ifndef UNREACHABLE_H
#define UNREACHABLE_H

#include <string>
#include <iostream>

#ifdef UNREACHABLE_IMPL
template<class T>
[[noreturn]]
constexpr T unreachable_impl(const char* file, unsigned int line, const char* func) {
	std::cerr << "[Fatal Error] unreachable reached\n";
	std::cerr << "\t in file " << file << ":" << line << "\n";
	std::cerr << "\t in function " << func << std::endl;
	exit(-1);
}
#else
[[noreturn]]
template<class T>
constexpr T unreachable_impl(const char* file, unsigned int line, const char* func) {
	return T{};
}
template<>
void unreachable_impl<void>(const char* file, unsigned int line, const char* func) {}
#endif //UNREACHABLE_IMPL

#define UNREACHABLE(T)	unreachable_impl<T>(__FILE__, __LINE__, __func__)


#endif //UNREACHABLE_H