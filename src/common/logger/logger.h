#ifndef LOG_LOGGER_H
#define LOG_LOGGER_H

#include "event.h"
#include "sink.h"

#include "common/singleton.h"
#include "common/types.h"

#include <memory>
#include <vector>

//TODO: flushing thread

namespace Log {
	class Logger : public Singleton<Logger> {

		std::vector<Log::Event> events;
		std::vector<std::unique_ptr<Log::Sink>> sinks;

	public:

		using sink_handle_t = ptr<Log::Sink>;

		Logger();
		~Logger();
		void log(Event);
		void flush();

		template<typename T, typename... Args>
		sink_handle_t registerSink(Args&&...) {
			//TODO: emplace back a unique prt after
			//perfect forwarding the arguments
			return nullptr;
		}
		void unregisterSink(sink_handle_t);
		ptr<Log::Sink> getSink(sink_handle_t);

	};
}

#endif //LOG_LOGGER_H
