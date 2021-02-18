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
    int listen_mode;
    struct sockaddr_storage local_addr, peer_addr;
    socklen_t local_addrlen, peer_addrlen;
    ev_io io;

    udp_recv_fn recv_cb;
};

void
udp_init(struct udp_context *udp, int listen_mode, const struct sockaddr *addr, socklen_t addrlen, udp_recv_fn recv_cb);

void udp_start(struct udp_context *udp);

void udp_stop(struct udp_context *udp);

void udp_peer_lock(struct udp_context *udp, const struct sockaddr *addr, socklen_t addrlen);

static inline int udp_peer_is_locked(struct udp_context *udp) {
    return udp->peer_addrlen == 0;
}

/**
 * Send a udp message
 * @param udp
 * @param msg
 * @param len
 * @return
 */
ssize_t udp_send(struct udp_context *udp, const uint8_t *msg, socklen_t len);

#endif //SIMPLE_TUN_UDP_H
