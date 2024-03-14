if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(SYSTEM_NAME "linux")
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(SYSTEM_NAME "osx")
else()
    message(FATAL_ERROR "Unknown operating system: ${CMAKE_SYSTEM_NAME}")
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(PROCESSOR_NAME "x64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    set(PROCESSOR_NAME "arm64")
else()
    message(FATAL_ERROR "Unknown processor name: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(BCOS_UTILITIES_PROJECT BcosUtilitiesProject)

set(VCPKG_BUILD_PATH ${CMAKE_CURRENT_SOURCE_DIR}/deps/src/${BCOS_UTILITIES_PROJECT}/vcpkg_installed/${PROCESSOR_NAME}-${SYSTEM_NAME})
message("vcpkg build path: ${VCPKG_BUILD_PATH}")
set(VCPKG_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/deps/src/${BCOS_UTILITIES_PROJECT}/vcpkg_installed/${PROCESSOR_NAME}-${SYSTEM_NAME}/lib)
message("vcpkg lib path: ${VCPKG_LIB_PATH}")
set(VCPKG_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/deps/src/${BCOS_UTILITIES_PROJECT}/vcpkg_installed/${PROCESSOR_NAME}-${SYSTEM_NAME}/include)
message("vcpkg include path: ${VCPKG_INCLUDE_PATH}")

#include
include_directories(${VCPKG_INCLUDE_PATH})

#lib
#unit_test_framework
set(BOOST_UNIT_TEST ${VCPKG_LIB_PATH}/libboost_unit_test_framework.a)

#log
set(BOOST_LOG ${VCPKG_LIB_PATH}/libboost_log.a)

#log_setup
set(BOOST_LOG_SETUP ${VCPKG_LIB_PATH}/libboost_log_setup.a)

#filesystem
set(BOOST_FILESYSTEM ${VCPKG_LIB_PATH}/libboost_filesystem.a)

#chrono
set(BOOST_CHRONO ${VCPKG_LIB_PATH}/libboost_chrono.a)

#thread
set(BOOST_THREAD ${VCPKG_LIB_PATH}/libboost_thread.a)

#serialization
set(BOOST_SERIALIZATION ${VCPKG_LIB_PATH}/libboost_serialization.a)

#iostreams
set(BOOST_IOSTREAMS ${VCPKG_LIB_PATH}/libboost_iostreams.a)

#system
set(BOOST_SYSTEM ${VCPKG_LIB_PATH}/libboost_system.a)

#zlib
set(ZLIB ${VCPKG_LIB_PATH}/libz.a)
