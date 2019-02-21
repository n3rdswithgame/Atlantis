#include "console.h"

#include <chrono>
#include <iostream>

#include "format.h"
#include "common/unreachable.h"

namespace chrono = std::chrono;

template<>
struct fmt::formatter<Log::Level> {
	
	template <typename ParseContext>
	constexpr auto parse(ParseContext &ctx) { return ctx.begin(); }

	template <typename FormatContext>
	auto format(const Log::Level &lvl, FormatContext &ctx) {
		#define tostr(lvl)					\
			case Log::Level::lvl:					\
			return format_to(ctx.out(), #lvl)
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
		return UNREACHABLE(decltype(format_to(ctx.out(), "")));	
	}
};

namespace Log::sink {
	void Console::sinkEvent(const Log::Event& e) {
		using chrono::duration_cast;
		using fsec = chrono::duration<float>;
		
		{
			Log::format::logger_format_guard color(e.lvl);

			//{0} level
			//{1} timestamp
			//{2} msg formated during the creation of the log event
			//{3} file
			//{4} line
			//{5} func
			//fmt::print("[{0} {1:.4f} in {3}:{5}:{4}]{2}", e.lvl, duration_cast<fsec>(e.timestamp).count(), e.msg, e.file, e.line, e.func);
			fmt::print("[{0} {1:.4f}] {2}", e.lvl, duration_cast<fsec>(e.timestamp).count(), e.msg, e.file, e.line, e.func);
		}

		std::cout<<'\n'; // fix the issue with background color bleeding into new lines
	}
} //namespace Log::sink