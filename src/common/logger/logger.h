#ifndef LOG_LOGGER_H
#define LOG_LOGGER_H

#include "event.h"
#include "sink.h"

#include "common/singleton.h"
#include "common/types.h"

#include <memory>
#include <mutex>
#include <vector>

//TODO: flushing thread

namespace Log {
	class Logger : public Singleton<Logger> {
		constexpr size_t static EVENT_THREASHOLD = 100;

		std::mutex logger_lock;

		std::vector<Log::Event> events;
		std::vector<std::unique_ptr<Log::Sink>> sinks;

	public:

		using sink_handle_t = ptr<Log::Sink>;

		Logger();
		~Logger();
		void log(Event);
		void flush();

		template<typename T, typename... Args>
		sink_handle_t registerSink(Args&&... args) {
			
			// probably a bad idea, but for simplicity using the adderss of the pointer as a 
			// handle as it is unique (thanks to the unique_ptr), probably will change this
			// at some later point
			std::lock_guard guard(logger_lock);
			return sinks.emplace_back(
					static_cast<Sink*>(
						new T(
							std::forward<Args>(args)...
						)
					)
				).get();
		}
		
		void unregisterSink(sink_handle_t);
		//ptr<Log::Sink> getSink(sink_handle_t);

	};
}

#endif //LOG_LOGGER_H
