include_directories(c/)

file(GLOB_RECURSE CRYPTONITE_SOURCE c/*.*)

add_library(cryptonite STATIC ${CRYPTONITE_SOURCE})
target_link_libraries(cryptonite pthread)