add_library(common STATIC
	constexpr.h

	endian.h

	file.h

	singleton.h

	small_vec.h

	tuple.h

	types.h

	unreachable.h

	bit/mask.h

	logger.h
	logger/event.h
	logger/event.cc
	logger/level.h
	logger/logger.h
	logger/logger.cc
	logger/sink.h
	logger/sinks/console.h
	logger/sinks/console.cc
	logger/sinks/format.h
	logger/sinks/format.cc


)

target_link_libraries(common PUBLIC fmt rang-format)
target_link_libraries(common PRIVATE project_warnings)
