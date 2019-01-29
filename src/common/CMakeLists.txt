add_library(common STATIC
	constexpr.h

	format.h
	format.cc

	logger.h
	logger.cc

	singleton.h

	types.h

	unreachable.h
)

target_link_libraries(common PUBLIC fmt rang-format)
target_link_libraries(common PRIVATE project_warnings)
