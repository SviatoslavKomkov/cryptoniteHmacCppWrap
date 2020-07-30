include_directories(cpp)

file(GLOB HMAC_TEST_SOURCE cpp/testHmac.cpp)

add_executable(test_Hmac ${HMAC_TEST_SOURCE})
target_link_libraries(test_Hmac hmacpp)