#include "format.h"

#include <iosfwd>

#include <fmt/format.h>
#include <rang.hpp>

#include "common/logger/level.h"

#include "common/unreachable.h"

namespace Log::format {
	logger_format_guard::logger_format_guard(Log::Level lvl) {
		using namespace rang;

		#define ignore(x)						\
			case Log::Level::x: break

		switch(lvl) {
			case Log::Level::Debug:
				return;
			case Log::Level::Status:
				std::cout << fgB::blue;
				return;
			case Log::Level::Warning:
				std::cout << fgB::cyan;
				return;
			case Log::Level::Error:
				std::cout << bg::green;
				return;
			case Log::Level::Critical:
				std::cout << bg::yellow;
				return;
			case Log::Level::Fatal:
				std::cout << bg::red;
				return;

			ignore(Count);
		};

		UNREACHABLE(int);


		#undef ignore

	}

	logger_format_guard::~logger_format_guard() {
		reset();
	}

	void logger_format_guard::reset() {
		using namespace rang;
		std::cout << fg::reset  << bg::reset << style::reset;
	}



} //namespace format