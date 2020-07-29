include_directories(cpp)

file(GLOB HMAC_SOURCE cpp/*.cpp)

add_library(cryptoniteWrap STATIC ${HMAC_SOURCE})
target_link_libraries(cryptoniteWrap cryptonite pthread)