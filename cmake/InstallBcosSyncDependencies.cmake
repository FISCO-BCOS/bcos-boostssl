hunter_add_package(bcos-sync)
find_package(bcos-framework CONFIG REQUIRED)
find_package(bcos-sync CONFIG REQUIRED)
get_target_property(BCOS_TXPOOL_INCLUDE bcos-sync::block-sync INTERFACE_INCLUDE_DIRECTORIES)
include_directories(${BCOS_TXPOOL_INCLUDE}/bcos-sync)