cmake_minimum_required (VERSION 3.0)
project(libkatran_testing)
find_library(BOOST_FS boost_filesystem)
find_library(BOOST_SYSTEM libboost_system.a boost_system)
find_library(BOOST_REGEX libboost_regex.a boost_regex)
find_library(BOOST_PROGOPT boost_program_options)
find_library(LIBDL dl)
find_library(LIBDOUBLE_CONVERT double-conversion)
find_library(LIBIBERTY iberty)
find_library(LIBCRYPTO crypto)

add_library(base64_helpers STATIC
    Base64Helpers.h
    Base64Helpers.cpp
)

target_link_libraries(base64_helpers
    "${GLOG}"
    "${GFLAGS}"
    "${FOLLY}"
    "${BOOST_SYSTEM}"
    "${BOOST_FS}"
    "${BOOST_REGEX}"
    "${BOOST_PROGOPT}"
    "${LIBDL}"
    "${LIBDOUBLE_CONVERT}"
    "${LIBIBERTY}"
    "${LIBCRYPTO}"
)

add_library(pcap_parser STATIC
    PcapParser.h
    PcapParser.cpp
    PcapStructs.h
)

target_link_libraries(pcap_parser
    base64_helpers
    "${FOLLY}"
    "${GLOG}"
    "${PTHREAD}"
    "${BOOST_SYSTEM}"
    "${BOOST_REGEX}"
)

add_library(xdptester STATIC
    XdpTester.h
    XdpTester.cpp
    KatranTestFixtures.h
    KatranOptionalTestFixtures.h
)

target_link_libraries(xdptester
    "${FOLLY}"
    "${GLOG}"
    "${PTHREAD}"
    "${BOOST_SYSTEM}"
    "${BOOST_REGEX}"
    pcap_parser
    bpfadapter
)

add_executable(katran_tester katran_tester.cpp)

target_link_libraries(katran_tester
    "${GFLAGS}"
    "${PTHREAD}"
    "${BOOST_REGEX}"
    xdptester
    katranlb
)

enable_testing()

add_executable(base64helpers-tests Base64Test.cpp)
target_link_libraries(base64helpers-tests
    "${GTEST}"
    "${GLOG}"
    "${GFLAGS}"
    "${PTHREAD}"
    "${LIBUNWIND}"
    "${LIBLZMA}"
    base64_helpers
)
add_test(Base64Tests base64helpers-tests)
