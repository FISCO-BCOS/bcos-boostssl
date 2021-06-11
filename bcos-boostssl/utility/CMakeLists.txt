set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSTATICLIB")

file(GLOB SRC_LIST "*.cpp")
file(GLOB HEADERS "*.h")

add_library(${UTILITY_TARGET} ${SRC_LIST} ${HEADERS})
target_link_libraries(${UTILITY_TARGET} Boost::system Boost::filesystem)
target_compile_options(${UTILITY_TARGET} PRIVATE -Wno-error -Wno-unused-variable)