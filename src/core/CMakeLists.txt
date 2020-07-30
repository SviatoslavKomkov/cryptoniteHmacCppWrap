include_directories(cpp)

file(GLOB SOURCES cpp/*.cpp)

add_library(hmacpp STATIC ${SOURCES})
target_link_libraries(hmacpp cryptonite pthread)