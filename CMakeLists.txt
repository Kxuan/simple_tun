cmake_minimum_required(VERSION 3.0)
project(simple_tun C)

find_package(PkgConfig REQUIRED)

set(CMAKE_C_STANDARD 11)
add_definitions(-D_GNU_SOURCE)

pkg_check_modules(CARES REQUIRED IMPORTED_TARGET libcares)

add_executable(simple_tun
        src/tun.c
        src/udp.c
        src/udp.h
        src/resolver.c
        src/resolver.h
        )
target_link_libraries(simple_tun PUBLIC ev)
target_link_libraries(simple_tun PUBLIC mbedcrypto)
target_link_libraries(simple_tun PUBLIC PkgConfig::CARES)

add_executable(udp_relay udp_relay.c)
target_link_libraries(udp_relay PUBLIC ev)