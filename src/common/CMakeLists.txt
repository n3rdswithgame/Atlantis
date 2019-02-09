add_library(common STATIC
	constexpr.h

	endian.h


	logger.h
	logger/event.h
	logger/event.cc
	logger/format.cc
	logger/format.h
	logger/level.h
	logger/logger.h
	logger/logger.cc
	logger/sink.h

	singleton.h

	types.h

	unreachable.h
)

target_link_libraries(common PUBLIC fmt rang-format)
target_link_libraries(common PRIVATE project_warnings)
