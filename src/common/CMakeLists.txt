add_library(common STATIC
	logger.h
	logger.cc
)

target_link_libraries(common PUBLIC fmt)
target_link_libraries(common PRIVATE project_warnings)
