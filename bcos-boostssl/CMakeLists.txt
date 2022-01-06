
aux_source_directory(context SRCS)
aux_source_directory(httpserver SRCS)
aux_source_directory(websocket SRCS)

add_library(${BOOSTSSL_TARGET} ${SRCS})
target_link_libraries(${BOOSTSSL_TARGET} ${UTILITIES_TARGET} Boost::system Boost::filesystem Boost::system
Boost::log Boost::chrono Boost::iostreams Boost::thread OpenSSL::SSL OpenSSL::Crypto)

# install bcos-boostssl
install(
    TARGETS ${BOOSTSSL_TARGET}
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)