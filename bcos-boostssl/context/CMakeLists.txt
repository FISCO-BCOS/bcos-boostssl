set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSTATICLIB")

file(GLOB SRC_LIST "*.cpp")
file(GLOB HEADERS "*.h")

add_library(${BOOSTSSL_CONTEXT_TARGET} ${SRC_LIST} ${HEADERS})
target_link_libraries(${BOOSTSSL_CONTEXT_TARGET} Boost::system Boost::filesystem)
target_compile_options(${BOOSTSSL_CONTEXT_TARGET} PRIVATE -Wno-error -Wno-unused-variable)