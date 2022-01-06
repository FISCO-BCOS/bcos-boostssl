hunter_config(
    Boost VERSION "1.76.0-local"
    URL
    "https://osp-1257653870.cos.ap-guangzhou.myqcloud.com/FISCO-BCOS/FISCO-BCOS/deps/boost_1_76_0.tar.bz2
    https://downloads.sourceforge.net/project/boost/boost/1.76.0/source/boost_1_76_0.tar.bz2
    https://nchc.dl.sourceforge.net/project/boost/boost/1.76.0/boost_1_76_0.tar.bz2"
    SHA1
    8064156508312dde1d834fec3dca9b11006555b6
    CMAKE_ARGS
    # CONFIG_MACRO=BOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX;BOOST_ALL_DYN_LINK
)

hunter_config(bcos-utilities
	VERSION 3.0.0-local
	URL https://${URL_BASE}/FISCO-BCOS/bcos-utilities/archive/5cfd3960f4b87b6d61ea479cbe5ae1bd20ff12c8.tar.gz
	SHA1 a25da3f97cde57c44a510611f29af0737f7b5199
)