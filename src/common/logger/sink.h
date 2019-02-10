#ifndef LOG_SINK_H
#define LOG_SINK_H

#include "event.h"
#include "level.h"

namespace Log {
	class Sink {
		Level filter = Level::Debug;
	protected:
		bool passesFilter(Level f) {
			return filter <= f;
		}
	public:
		Sink() = default;
		virtual ~Sink() = default;
		virtual void sinkEvent(const Log::Event&) = 0;

		void setFilter(Level f) {
			filter = f;
		}

		Level getFilter() {
			return filter;
		}
	};
} //naemspace Log

#endif