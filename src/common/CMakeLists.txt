add_library(common STATIC
	constexpr.h

	endian.h


	logger.h
	logger/event.h
	logger/event.cc
	logger/level.h
	logger/logger.h
	logger/logger.cc
	logger/sink.h
	logger/sinks/format.h
	logger/sinks/format.cc
	logger/sinks/console.h
	logger/sinks/console.cc

	singleton.h

	types.h

	unreachable.h
)

target_link_libraries(common PUBLIC fmt rang-format)
target_link_libraries(common PRIVATE project_warnings)
