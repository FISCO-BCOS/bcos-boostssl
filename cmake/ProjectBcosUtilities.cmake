include(ExternalProject)

ExternalProject_Add(BcosUtilitiesLib
    PREFIX ${CMAKE_SOURCE_DIR}/deps
    GIT_REPOSITORY https://github.com/Shareong//bcos-utilities.git
    GIT_TAG a59f0673386a82c8ed89d88690264e1b02bc7347
    BUILD_IN_SOURCE 1
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1
)

ExternalProject_Get_Property(BcosUtilitiesLib INSTALL_DIR)
add_library(bcos-utilities STATIC IMPORTED)
set(BCOS_UTILITIES_LIBRARY ${INSTALL_DIR}/lib/libbcos-utilities.a)
set(BCOS_UTILITIES_INCLUDE_DIR ${INSTALL_DIR}/include)
file(MAKE_DIRECTORY ${INSTALL_DIR}/lib)  # Must exist.
file(MAKE_DIRECTORY ${BCOS_UTILITIES_INCLUDE_DIR})  # Must exist.
set_property(TARGET bcos-utilities PROPERTY IMPORTED_LOCATION ${BCOS_UTILITIES_LIBRARY})
set_property(TARGET bcos-utilities PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${BCOS_UTILITIES_INCLUDE_DIR})
add_dependencies(bcos-utilities BcosUtilitiesLib)
unset(INSTALL_DIR)
