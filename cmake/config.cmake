hunter_config(
    Boost VERSION "1.83"
    URL "https://psychz.dl.sourceforge.net/project/boost/boost/1.83.0/boost_1_83_0.tar.bz2"
    SHA1 75b1f569134401d178ad2aaf97a2993898dd7ee3
    CMAKE_ARGS CONFIG_MACRO=BOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX 
)

# hunter_config(bcos-utilities VERSION 1.0.0
#     URL https://github.com/Shareong//bcos-utilities/archive/a59f0673386a82c8ed89d88690264e1b02bc7347.tar.gz
# 	SHA1 7b0ef2ea5c05b7c71b39875cd0df94a5670b0e57
# )

hunter_config(OpenSSL VERSION tassl_1.1.1b_v1.4-local
    URL https://${URL_BASE}/FISCO-BCOS/TASSL-1.1.1b/archive/f9d60fa510e5fbe24413b4abdf1ea3a48f9ee6aa.tar.gz
    SHA1 e56121278bf07587d58d154b4615f96575957d6f
)
