#include <string_view>

#include "event.h"

namespace Log {

	constexpr std::string_view StripPath(std::string_view file) {
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

	Event Event::MakeImpl(Level lvl, const std::string& file, unsigned int line, const std::string& func,
		const std::string& msg, const fmt::format_args& args)
	{
		using chrono::duration_cast;
		using chrono::steady_clock;

		static steady_clock::time_point t_zero = steady_clock::now();

		Event event;
		event.timestamp = duration_cast<timestamp_t>(steady_clock::now() - t_zero);
		event.lvl = lvl;
		event.msg = fmt::vformat(msg, args);

		event.file = StripPath(file);
		event.line = line;
		event.func = func;

		return event;
	}
} //namespace Log