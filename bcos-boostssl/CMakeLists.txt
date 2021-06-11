file(GLOB SRC_LIST "*.cpp")
file(GLOB HEADERS "*.h")

add_subdirectory(network)
add_subdirectory(utility)
add_subdirectory(context)

add_library(${BOOSTSSL_TARGET} ${SRC_LIST} ${HEADERS})
target_link_libraries(${BOOSTSSL_TARGET} PUBLIC OpenSSL::SSL OpenSSL::Crypto ${NETWORK_TARGET} ${UTILITY_TARGET})
target_compile_options(${BOOSTSSL_TARGET} PRIVATE -Wno-error -Wno-unused-variable)