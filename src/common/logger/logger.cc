#include "logger.h"

#include <algorithm>

#include "common/unreachable.h"

#include "sinks/console.h"


namespace Log {

	Logger::Logger() {
		// want to reserve the space and leave size = 0
		// not default construct all of the elements

		//TODO: figure out a good number for this
		// instead of pulling out a magic 100;
		events.reserve(EVENT_THREASHOLD);

		registerSink<sink::Console>();

		//std::unique_ptr<Sink> console(new sink::Console());
		//sinks.emplace_back(std::move(make_unique<Sink>(console)));
	}

	Logger::~Logger() {
		flush();
	}

	void Logger::log(Event e) {
		{
			std::lock_guard guard(logger_lock);
			events.push_back(std::move(e));
		}
		if(events.size() > (2 * EVENT_THREASHOLD) ){
			flush();
		}
	}

	void Logger::flush() {
		std::vector<Log::Event> tmp;

		{
			std::lock_guard guard(logger_lock);

			//swap out events into a temporary vector, and then replace events with a shiny new vector
			tmp = std::exchange(events, std::vector<Log::Event>{});
			events.reserve(EVENT_THREASHOLD);
		}

		//if there are no sinks don't bother looping over the events
		if(sinks.size() != 0) {
			//do the iteration this way to try and mitigate the impact of the indirect call
			//by calling the same sinkEvent multiple times, it hopefully keeps that function
			//hot in icache 
			for(auto& sink : sinks) {
				for(auto e : tmp) {
					sink->sinkEvent(e);
				}
			}
		}
	}

	void Logger::unregisterSink(sink_handle_t h) {
		std::lock_guard guard(logger_lock);

		sinks.erase(
			std::remove_if(sinks.begin(), sinks.end(), [=](auto& sink) {return sink.get() == h;}),
			sinks.end()
		);
	}

} //namespace Log