#ifndef FORMAT_H
#define FORMAT_H

namespace Log {
	enum class Level;

	namespace format {
		class logger_format_guard {
		public:
			logger_format_guard(Log::Level);
			~logger_format_guard();
			void reset();
		};
	} //namespace Log::format
} //namespace Log

#endif //FORMAT_H