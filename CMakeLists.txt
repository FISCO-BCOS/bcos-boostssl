#------------------------------------------------------------------------------
# Top-level CMake file for bcos-boostssl
# ------------------------------------------------------------------------------
# Copyright (C) 2021 bcos-boostssl
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.10)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version")

include(FetchContent)
if (NOT DEFINED URL_BASE)
    set(URL_BASE "github.com")
    # set(URL_BASE "github.com.cnpmjs.org")
endif()

# set(BCOS_CMAKE_SCRIPTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bcos-cmake-scripts)
# FetchContent_Declare(bcos-cmake-scripts
#    GIT_REPOSITORY https://${URL_BASE}/FISCO-BCOS/bcos-cmake-scripts.git
#    GIT_TAG dev
#    SOURCE_DIR ${BCOS_CMAKE_SCRIPTS_DIR}
# )
# FetchContent_MakeAvailable(bcos-cmake-scripts)

set(BCOS_BOOSTSSL_CMAKE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake" CACHE PATH "The cmake path for the library")
# list(APPEND CMAKE_MODULE_PATH ${BCOS_CMAKE_SCRIPTS_DIR})
list(APPEND CMAKE_MODULE_PATH ${BCOS_BOOSTSSL_CMAKE_DIR})

#init hunter
include(HunterGate)
HunterGate(
    URL "https://${URL_BASE}/FISCO-BCOS/hunter/archive/b55a347258b0fc3eda47f4ccd3e2c0db595b4957.tar.gz"
    SHA1 "9331d1e70cee5498bd59ada13aa68278cbb9a2d6"
    FILEPATH "${CMAKE_SOURCE_DIR}/cmake/config.cmake"
)

project(bcos-boostssl VERSION "1.0.0")
set(VERSION_SUFFIX "")

# basic settings
include(Options)
configure_project()
include(CompilerSettings)

# Boost
hunter_add_package(Boost COMPONENTS all)
find_package(Boost CONFIG REQUIRED log chrono system filesystem thread)

# OpenSSL
hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED REQUIRED)

# JsonCpp
hunter_add_package(jsoncpp)
find_package(jsoncpp CONFIG REQUIRED)

include_directories(${CMAKE_INSTALL_INCLUDEDIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_INSTALL_INCLUDEDIR}/include)

# install dependencies
# include(InstallBcosFrameworkDependencies)

set(BOOSTSSL_UTILITIES_TARGET "boostssl-utilities")
set(BOOSTSSL_CONTEXT_TARGET "boostssl-context")
set(BOOSTSSL_HTTPSERVER_TARGET "boostssl-httpserver")
set(BOOSTSSL_WEBSOCKET_TARGET "boostssl-websocket")

add_subdirectory(bcos-boostssl)

# TODO: remove ut temp for remove bcos-framework deps
# ut
# if (TESTS)
#    enable_testing()
#    set(CTEST_OUTPUT_ON_FAILURE TRUE)
#    add_subdirectory(test)
# endif()

if (BUILD_EXEC_TEST)
    add_subdirectory(test/exec)
endif()

include(InstallConfig)

# install utilities target
install(
    TARGETS ${BOOSTSSL_UTILITIES_TARGET}
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# install ssl context target
install(
    TARGETS ${BOOSTSSL_CONTEXT_TARGET}
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# install httpserver target
install(
    TARGETS ${BOOSTSSL_HTTPSERVER_TARGET}
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# install websocket target
install(
    TARGETS ${BOOSTSSL_WEBSOCKET_TARGET}
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# install the include files for hash
include(InstallInclude)

# for code coverage
# if (COVERAGE)
#     include(Coverage)
#     config_coverage("boostssl-coverage" "'/usr*' '${CMAKE_CURRENT_SOURCE_DIR}/bcos-cmake-scripts*' '${CMAKE_SOURCE_DIR}/test/mock**' '${CMAKE_SOURCE_DIR}/test/main**'")
# endif ()
