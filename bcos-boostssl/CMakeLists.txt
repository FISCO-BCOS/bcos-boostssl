
file(GLOB_RECURSE SRCS "*.cpp")
file(GLOB_RECURSE HEADERS "*.h")

add_library(${BOOSTSSL_TARGET} ${SRCS} ${HEADERS})
target_link_libraries(${BOOSTSSL_TARGET} PUBLIC bcos-utilities OpenSSL::SSL OpenSSL::Crypto)
