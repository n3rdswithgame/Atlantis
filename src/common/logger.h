#ifndef LOGGER_H
#define LOGGER_H

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include <fmt/format.h>

#include "singleton.h"

namespace chrono = std::chrono;


namespace Log {
	enum class Level {
		Debug,
		Status,
		Warning,
		Error,
		Critical,
		Fatal,


		Count

	};
	
	std::string LevelToString();

	struct LogEvent{
		//TODO: log to file

		using timestamp_t = chrono::microseconds;

		timestamp_t timestamp;
		Level lvl;
		std::string msg;

		std::string file;
		unsigned int line;
		std::string func;

		template <typename... Args>
		static LogEvent Make(
			Level lvl, std::string file, unsigned int line, std::string func,
			std::string msg, const Args&... args)
		{
			return MakeImpl(lvl, file, line, func, msg, fmt::make_format_args(args...));
		}

		static LogEvent MakeImpl(Level lvl, std::string file, unsigned int line, std::string func,
			std::string msg, const fmt::format_args& args);
	};

	class Logger : public Singleton<Logger> {
		FILE* logFile;
	public:
		Logger();
		~Logger();
		void log(LogEvent);
	};

} //namespace log

//Old system

//#define MAKE_EVENT(lvl, msg, ...) 
//	::Log::LogEvent::Make(lvl, __FILE__, __LINE__, __func__, msg __VA_OPT__(,) __VA_ARGS__)
//
//#define LOG_EVENT(lvl, msg, ...) 
//	::Log::Logger::get().log(MAKE_EVENT(lvl, msg, __VA_ARGS__))
//
//#define DEBUG_EVENT(msg, ...)				LOG_EVENT(::Log::Level::Debug, 			msg, __VA_ARGS__)
//#define STATUS_EVENT(msg, ...)				LOG_EVENT(::Log::Level::Status, 		msg, __VA_ARGS__)
//#define WARNING_EVENT(msg, ...)				LOG_EVENT(::Log::Level::Warning, 		msg, __VA_ARGS__)
//#define ERROR_EVENT(msg, ...)				LOG_EVENT(::Log::Level::Error, 			msg, __VA_ARGS__)
//#define CRITICAL_EVENT(msg, ...)			LOG_EVENT(::Log::Level::Critical, 		msg, __VA_ARGS__)
//#define FATAL_EVENT(msg, ...)				LOG_EVENT(::Log::Level::Fatal, 			msg, __VA_ARGS__)
//
//#define DEBUG(msg, ...)						DEBUG_EVENT		(msg, __VA_ARGS__)
//#define STATUS(msg, ...)					STATUS_EVENT	(msg, __VA_ARGS__)
//#define WARNING(msg, ...)					WARNING_EVENT	(msg, __VA_ARGS__)
//#define ERROR(msg, ...)						ERROR_EVENT		(msg, __VA_ARGS__)
//#define CRITICAL(msg, ...)					CRITICAL_EVENT	(msg, __VA_ARGS__)
//#define FATAL(msg, ...)						FATAL_EVENT		(msg, __VA_ARGS__)

//This use to be a lot nicer but clang doesn't like the nested macros
//TODO: figure out why the nested macros don't work on clang

#define DEBUG(...)											\
	(::Log::Logger::get().log(								\
		::Log::LogEvent::Make(::Log::Level::Debug,			\
			__FILE__, __LINE__, __func__, __VA_ARGS__)))

#define STATUS(...)											\
	(::Log::Logger::get().log(								\
		::Log::LogEvent::Make(::Log::Level::Status,			\
			__FILE__, __LINE__, __func__, __VA_ARGS__)))

#define WARNING(...)										\
	(::Log::Logger::get().log(								\
		::Log::LogEvent::Make(::Log::Level::Warning,		\
			__FILE__, __LINE__, __func__, __VA_ARGS__)))

#define ERROR(...)											\
	(::Log::Logger::get().log(								\
		::Log::LogEvent::Make(::Log::Level::Error,			\
			__FILE__, __LINE__, __func__, __VA_ARGS__)))

#define CRITICAL(...)										\
	(::Log::Logger::get().log(								\
		::Log::LogEvent::Make(::Log::Level::Critical,		\
			__FILE__, __LINE__, __func__, __VA_ARGS__)))

#define FATAL(...)											\
	(::Log::Logger::get().log(								\
		::Log::LogEvent::Make(::Log::Level::Fatal,			\
			__FILE__, __LINE__, __func__, __VA_ARGS__)))

#endif //LOGGER_H