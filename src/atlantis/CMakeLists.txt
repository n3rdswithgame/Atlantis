add_executable(atlantis
	cli.h

	main.cc

	ver.h
)

target_link_libraries(atlantis PUBLIC capstone clara)
target_link_libraries(atlantis PUBLIC common core)
target_link_libraries(atlantis PRIVATE project_warnings)