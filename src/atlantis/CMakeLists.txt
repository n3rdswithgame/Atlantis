add_executable(atlantis
	main.cc
)

target_link_libraries(atlantis PUBLIC capstone clipp)
target_link_libraries(atlantis PUBLIC common core)
target_link_libraries(atlantis PRIVATE project_warnings)