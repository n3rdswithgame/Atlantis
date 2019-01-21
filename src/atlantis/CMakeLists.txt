add_executable(atlantis
	main.cc
)

target_link_libraries(atlantis PUBLIC capstone)
target_link_libraries(atlantis PUBLIC common)
target_link_libraries(atlantis PRIVATE project_warnings)