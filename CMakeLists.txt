cmake_minimum_required(VERSION 3.8)

project(Atlantis)

set(CMAKE_CXX_STANDARD 17)

set(BUILD_DIR ${PROJECT_BINARY_DIR})
set(LIB_DIR lib)
set(BUILT_LIB ${BUILD_DIR}/${LIB_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

set(UNREACHABLE_IMPL ON)

if(UNREACHABLE_IMPL)
    add_compile_definitions(UNREACHABLE_IMPL)
endif()

add_subdirectory(${LIB_DIR})

add_library(project_warnings INTERFACE)
if(MSVC)
    target_compile_options(project_warnings INTERFACE /W4)
else()
    target_compile_options(project_warnings
                         INTERFACE
                         -Wall
                         -Wextra
                         -Wshadow # warn the user if a variable declaration shadows one from a
                                  # parent context
                         -Wnon-virtual-dtor # warn the user if a class with virtual functions has a
                                            # non-virtual destructor. This helps catch hard to
                                            # track down memory errors
                         -Wold-style-cast # warn for c-style casts
                         -Wcast-align # warn for potential performance problem casts
                         -Wunused # warn on anything being unused
                         -Woverloaded-virtual # warn if you overload (not override) a virtual
                                              # function
                         -Wpedantic # warn if non-standard C++ is used
                         -Wconversion # warn on type conversions that may lose data
                         -Wsign-conversion # warn on sign conversions
                         -Wmisleading-indentation # warn if identation implies blocks where blocks
                                                  # do not exist
                         -Wduplicated-cond # warn if if / else chain has duplicated conditions
                         -Wduplicated-branches # warn if if / else branches have duplicated code
                         -Wlogical-op # warn about logical operations being used where bitwise were
                                      # probably wanted
                         -Wnull-dereference # warn if a null dereference is detected
                         -Wuseless-cast # warn if you perform a cast to the same type
                         -Wdouble-promotion # warn if float is implicit promoted to double
                         )
endif()


add_subdirectory(src)