/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SIMPLE_TUN_UDP_H
#define SIMPLE_TUN_UDP_H

#include <sys/socket.h>
#include <ev.h>
#include <stdint.h>

struct udp_context;

typedef void (*udp_recv_fn)(struct udp_context *udp,
                            uint8_t *msg, size_t len,
                            struct sockaddr *addr, socklen_t addrlen
);

struct udp_context {
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    ev_io io;

    udp_recv_fn recv_cb;
};

void
udp_init(struct udp_context *udp, udp_recv_fn recv_cb, const struct sockaddr *local_addr, socklen_t local_addrlen);

void udp_start(struct udp_context *udp);

void udp_stop(struct udp_context *udp);


/**
 * Send a udp message
 * @param udp
 * @param msg
 * @param len
 * @return
 */
ssize_t udp_sendto(struct udp_context *udp,
                   const uint8_t *msg, socklen_t len,
                   const struct sockaddr *addr, socklen_t addrlen);

#endif //SIMPLE_TUN_UDP_H
