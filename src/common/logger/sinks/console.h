#ifndef LOG_SINK_CONSOLE_H
#define LOG_SINK_CONSOLE_H

#include "common/logger/sink.h"

namespace Log::sink {
	class Console : public Log::Sink {
	public:
		void sinkEvent(const Log::Event&) override;
	};
} //namespace Log::sink

#endif //LOG_SINK_CONSOLE_H