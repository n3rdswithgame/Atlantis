#include "logger.h"

#include <algorithm>

#include "format.h"

#include "common/unreachable.h"

template<>
struct fmt::formatter<Log::Level> {
	
	template <typename ParseContext>
	constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

	template <typename FormatContext>
	auto format(const Log::Level &lvl, FormatContext &ctx) {
		#define tostr(lvl)					\
			case Log::Level::lvl:					\
			return format_to(ctx.begin(), #lvl)
		#define ignore(x)						\
			case Log::Level::x: break

			switch(lvl) {
				tostr(Debug);
				tostr(Status);
				tostr(Warning);
				tostr(Error);
				tostr(Critical);
				tostr(Fatal);

				ignore(Count);
			}
		#undef tostr
			return UNREACHABLE(decltype(format_to(ctx.begin(), "")));	
		}
	};

namespace Log {

	std::string StripPath(std::string file) {
		size_t folder = file.find("./");
		if(folder != std::string::npos)
			return file.substr(folder + 2);

		folder = file.find("src/");
		if(folder != std::string::npos)
			return file.substr(folder+4);
		
		folder = file.find("tests/");
		if(folder != std::string::npos)
			return file.substr(folder+6);
		
		return file;
	}

	Event Event::MakeImpl(Level lvl, std::string file, unsigned int line, std::string func,
		std::string msg, const fmt::format_args& args)
	{
		using chrono::duration_cast;
		using chrono::steady_clock;

		static steady_clock::time_point t_zero = steady_clock::now();

		Event event;
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

	void Logger::log(Event e) {
		using chrono::duration_cast;
		using fsec = chrono::duration<float>;
		
		{
			format::logger_format_guard color(e.lvl);

			//{0} level
			//{1} timestamp
			//{2} msg formated during the creation of the log event
			//{3} file
			//{4} line
			//{5} func
			fmt::print("[{0} {1:.4f} in {3}:{5}:{4}]{2}", e.lvl, duration_cast<fsec>(e.timestamp).count(), e.msg, StripPath(e.file), e.line, e.func);
		}

		std::cout<<'\n'; // fix the issue with background color bleeding into new lines
	}

} //namespace Log