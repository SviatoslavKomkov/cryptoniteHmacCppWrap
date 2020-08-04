cmake_minimum_required(VERSION 3.05)
project(cryptonite-hmacpp VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(DEFAULT_BUILD_TYPE "Release")

add_definitions(-DCRYPTONITE_EXPORT=extern)

include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/core/cpp
)
add_subdirectory(src/core)
add_subdirectory(src/cryptonite)
add_subdirectory(src/tests)

if(CMAKE_BUILD_TYPE STREQUAL Release)
        add_definitions(-DNDEBUG)
        add_compile_options(-Werror -Wall)
        add_compile_options(-O2)
        add_compile_options(-march=native)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Debug)
        add_definitions(-DDEBUG)
        add_compile_options(-O0 -g)
endif()

# Install library
install(TARGETS hmacpp_static cryptonite DESTINATION lib)

# Install library headers
file(GLOB HEADERS ${CMAKE_SOURCE_DIR}/src/core/cpp/*.h)
install(FILES ${HEADERS} DESTINATION include)