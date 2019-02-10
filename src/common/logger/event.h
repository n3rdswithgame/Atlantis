#ifndef LOG_EVENT_H
#define LOG_EVENT_H

#include "level.h"

#include <chrono>
#include <string>
#include <string_view>

#include <fmt/format.h>

namespace chrono = std::chrono;

namespace Log {
	std::string LevelToString();

	struct Event{

		using timestamp_t = chrono::microseconds;

		timestamp_t timestamp;
		Level lvl;
		std::string msg;

		std::string file;
		unsigned int line;
		std::string func;

		template <typename... Args>
		static Event Make(Level lvl, std::string file, unsigned int line, std::string func,
			std::string msg, const Args&... args)
		{
			return MakeImpl(lvl, file, line, func, msg, fmt::make_format_args(args...));
		}

		static Event MakeImpl(Level lvl, const std::string& file, unsigned int line, const std::string& func,
			const std::string& msg, const fmt::format_args& args);
	};
} //namespace LOG

#endif