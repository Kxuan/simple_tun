cmake_minimum_required(VERSION 3.0)
project(simple_tun C)

set(CMAKE_C_STANDARD 11)
add_definitions(-D_GNU_SOURCE)

add_executable(simple_tun src/tun.c src/udp.c src/udp.h)
target_link_libraries(simple_tun PUBLIC ev)
target_link_libraries(simple_tun PUBLIC mbedcrypto)

add_executable(udp_relay udp_relay.c)
target_link_libraries(udp_relay PUBLIC ev)