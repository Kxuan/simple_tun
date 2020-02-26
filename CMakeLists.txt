cmake_minimum_required(VERSION 3.16)
project(simple_tun C)

set(CMAKE_C_STANDARD 11)
add_definitions(-D_GNU_SOURCE)

add_executable(simple_tun tun.c)
target_link_libraries(simple_tun PUBLIC ev)

add_executable(udp_relay udp_relay.c)
target_link_libraries(udp_relay PUBLIC ev)