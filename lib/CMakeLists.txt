
#########{fmt}#########
add_subdirectory(fmt)
add_library(fmt::fmt ALIAS fmt) #might be unneeded
#use target_link_libraries(foo PRIVATE fmt)

#######capstone########
#configure capstone to only build ARM32
set(CAPSTONE_BUILD_TESTS 			  OFF CACHE BOOL "docstring" FORCE)
set(CAPSTONE_BUILD_SHARED 			  OFF CACHE BOOL "docstring" FORCE)
set(CAPSTONE_BUILD_CSTOOL 			  OFF CACHE BOOL "docstring" FORCE)
option(CAPSTONE_ARM64_SUPPORT      "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_M680X_SUPPORT      "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_M68K_SUPPORT       "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_MIPS_SUPPORT       "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_PPC_SUPPORT        "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_SPARC_SUPPORT      "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_SYSZ_SUPPORT       "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_XCORE_SUPPORT      "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_X86_SUPPORT        "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_TMS320C64X_SUPPORT "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_M680X_SUPPORT      "" OFF) #disable capstone support for unneded archatecture
option(CAPSTONE_EVM_SUPPORT        "" OFF) #disable capstone support for unneded archatecture
##add capstone
add_subdirectory(capstone)
target_include_directories(capstone-static PUBLIC capstone/include)
add_library(capstone ALIAS capstone-static)
#use target_link_libraries(foo PRIVATE capstone-static)

#########json##########
set(JSON_BuildTests OFF CACHE BOOL "docstring" FORCE)
add_subdirectory(json)
#use target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)