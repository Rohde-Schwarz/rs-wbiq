cmake_minimum_required(VERSION 3.13)
project(dpdk_msr4_rx C CXX)

set(ENV{PKG_CONFIG_PATH} "/usr/local/lib64/pkgconfig/")

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)
pkg_check_modules(PC_ZeroMQ QUIET zmq)

message("-- Found DPDK, version " ${DPDK_VERSION})

add_definitions("-std=c++17")

#set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fPIC")
#set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -fPIC")

set(SOURCE_FILES
    ${CMAKE_SOURCE_DIR}/src/dpdk_msr4_rx.cpp
    ${CMAKE_SOURCE_DIR}/src/hrzrHeaderParser.cc
    )

add_executable(dpdk_msr4_rx ${SOURCE_FILES})

target_include_directories(dpdk_msr4_rx PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dpdk_msr4_rx ${DPDK_LIBRARIES} zmq)
target_compile_options(dpdk_msr4_rx PUBLIC ${DPDK_CFLAGS})
