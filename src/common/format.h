#ifndef FORMAT_H
#define FORMAT_H

#include "logger.h"

namespace format {
	class logger_format_guard {
	public:
		logger_format_guard(Log::Level);
		~logger_format_guard();
		void reset();
	};
} //namespace format

#endif //FORMAT_H