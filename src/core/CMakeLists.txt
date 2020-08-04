include_directories(cpp)

file(GLOB SOURCES cpp/*.cpp)

# static library target
add_library(hmacpp_static STATIC ${SOURCES})
set_target_properties(hmacpp_static PROPERTIES OUTPUT_NAME hmacpp)
target_link_libraries(hmacpp_static cryptonite pthread)

# shared library target
#add_library(hmacpp_shared SHARED ${SOURCES})
#set_target_properties(hmacpp_shared PROPERTIES OUTPUT_NAME hmacpp SOVERSION 1)
#target_link_libraries(hmacpp_shared cryptonite pthread)