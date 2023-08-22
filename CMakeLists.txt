cmake_minimum_required(VERSION 3.13)
project(dpdk_msr4_rx C CXX)

OPTION(USE_ZMQ "Forward the received IQ data using a ZMQ PUB pattern instead of writing it to disk." OFF)

set(ENV{PKG_CONFIG_PATH} "/usr/local/lib64/pkgconfig/")

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)
IF(USE_ZMQ)
    pkg_check_modules(PC_ZeroMQ QUIET zmq)
    message("-- Forwarding data using ZMQ instead of dumping to file!")
ENDIF()

message("-- Found DPDK, version " ${DPDK_VERSION})

add_definitions("-std=c++17")

#set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fPIC")
#set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -fPIC")

set(SOURCE_FILES
    ${CMAKE_SOURCE_DIR}/src/dpdk_msr4_rx.cpp
    ${CMAKE_SOURCE_DIR}/src/hrzrHeaderParser.cpp
    ${CMAKE_SOURCE_DIR}/src/util.cpp
    )

add_executable(dpdk_msr4_rx ${SOURCE_FILES})
target_compile_options(dpdk_msr4_rx PRIVATE -Wall -Wextra -Wpedantic -Werror)


IF(USE_ZMQ)
    target_compile_definitions(dpdk_msr4_rx PUBLIC FORWARD_ZMQ)
ENDIF()
target_include_directories(dpdk_msr4_rx PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dpdk_msr4_rx ${DPDK_LIBRARIES} zmq)
target_compile_options(dpdk_msr4_rx PUBLIC ${DPDK_CFLAGS})
