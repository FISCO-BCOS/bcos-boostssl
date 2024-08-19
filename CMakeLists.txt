# ------------------------------------------------------------------------------
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
# ------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.10)

include(FetchContent)

if(NOT DEFINED URL_BASE)
    set(URL_BASE "github.com")
    # set(URL_BASE "github.com.cnpmjs.org")
endif()

set(BCOS_BOOSTSSL_CMAKE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake" CACHE PATH "The cmake path for the library")
list(APPEND CMAKE_MODULE_PATH ${BCOS_BOOSTSSL_CMAKE_DIR})

# vcpkg init
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    find_package(Git REQUIRED)
    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

project(bcos-boostssl VERSION "1.0.0")

# basic settings
include(Options)
configure_project()
include(CompilerSettings)
include(BcosUtilitiesDependencies)
# OpenSSL
find_package(OpenSSL REQUIRED)

# JsonCpp
find_package(jsoncpp REQUIRED)

include_directories(${CMAKE_INSTALL_INCLUDEDIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_INSTALL_INCLUDEDIR}/include)

# install dependencies
# include(InstallBcosFrameworkDependencies)
set(BOOSTSSL_TARGET "bcos-boostssl")

include(InstallConfig)

# install the include files for hash
include(InstallInclude)

add_subdirectory(bcos-boostssl)

# install bcos-boostssl
install(
    TARGETS ${BOOSTSSL_TARGET}
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# TODO: remove ut temp for remove bcos-framework deps
# ut
if(TESTS)
    enable_testing()
    set(CTEST_OUTPUT_ON_FAILURE TRUE)
    add_subdirectory(test)
endif()

if(BUILD_SAMPLE)
    add_subdirectory(sample)
endif()
