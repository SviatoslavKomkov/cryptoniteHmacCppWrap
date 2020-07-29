include_directories(cpp)

file(GLOB HMAC_TEST_SOURCE cpp/testHmac.cpp)

add_executable(hmacTest ${HMAC_TEST_SOURCE})
target_link_libraries(hmacTest cryptoniteWrap)