add_library(common STATIC
	constexpr.h

	endian.h

	format.cc
	format.h

	logger.cc
	logger.h

	singleton.h

	types.h

	unreachable.h
)

target_link_libraries(common PUBLIC fmt rang-format)
target_link_libraries(common PRIVATE project_warnings)
