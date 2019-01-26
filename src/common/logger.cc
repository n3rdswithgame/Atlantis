#include "logger.h"

#include <algorithm>

#include "unreachable.h"

namespace Log {

	std::string LevelToStr(Level lvl) {
		#define tostr(lvl)					\
		case Level::lvl:					\
			return #lvl

		switch(lvl) {
			tostr(Debug);
			tostr(Status);
			tostr(Warning);
			tostr(Error);
			tostr(Critical);
			tostr(Fatal);

		default:
			return UNREACHABLE(std::string);
		}

		#undef tostr
	}

	std::string StripPath(std::string file) {
		size_t src = file.find("src/");
		return file.substr(src+4);
	}

	LogEvent LogEvent::MakeImpl(Level lvl, std::string file, unsigned int line, std::string func,
		std::string msg, const fmt::format_args& args)
	{
		using chrono::duration_cast;
		using chrono::steady_clock;

		static steady_clock::time_point t_zero = steady_clock::now();

		LogEvent event;
		event.timestamp = duration_cast<timestamp_t>(steady_clock::now() - t_zero);
		event.lvl = lvl;
		event.msg = fmt::vformat(msg, args);

		event.file = file;
		event.line = line;
		event.func = func;

		return event;
	}

	Logger::Logger() {
	}

	Logger::~Logger() {
	}

	void Logger::log(LogEvent e) {
		using chrono::duration_cast;
		using fsec = chrono::duration<float>;
		//{0} level
		//{1} timestamp
		//{2} msg
		//{3} file
		//{4} line
		//{5} func
		fmt::print("[{0}:{1:.5f} in {3}:{5}:{4}]{2}\n", LevelToStr(e.lvl), duration_cast<fsec>(e.timestamp).count(), e.msg, StripPath(e.file), e.line, e.func);
	}

} //namespace Log