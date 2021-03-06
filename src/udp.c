/* SPDX-License-Identifier: Apache-2.0 */

#include "udp.h"
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ev.h>

static uint8_t buffer_ciphertext[1 + 64 * 1024 + 16];

static void on_udp_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;
    struct sockaddr_storage addr;
    struct udp_context *udp = w->data;
    socklen_t addrlen = sizeof(&addr);

    n = recvfrom(w->fd, buffer_ciphertext, sizeof(buffer_ciphertext), MSG_DONTWAIT,
                 (struct sockaddr *) &addr, &addrlen);
    if (n < 1) {
        switch (errno) {
        case EMSGSIZE:
            fprintf(stderr, "udp: message too large. Decrease your MTU on the tap/tun interface.\n");
            break;
        case EINTR:
        case EAGAIN:
            break;
        default:
            perror("udp: recv");
            exit(1);
        }
        return;
    }
    udp->recv_cb(udp, buffer_ciphertext, n, (struct sockaddr *) &addr, addrlen);
}

void udp_init(struct udp_context *udp, udp_recv_fn recv_cb,
              const struct sockaddr *local_addr, socklen_t local_addrlen) {
    if (local_addrlen == 0) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &udp->local_addr;
        addr->sin6_port = 0;
        addr->sin6_family = AF_INET6;
        addr->sin6_addr = (struct in6_addr) IN6ADDR_ANY_INIT;
        udp->local_addrlen = sizeof(*addr);
    } else {
        memcpy(&udp->local_addr, local_addr, local_addrlen);
        udp->local_addrlen = local_addrlen;
    }

    ev_io_init(&udp->io, on_udp_callback, -1, EV_READ);
    udp->io.data = udp;
    udp->recv_cb = recv_cb;
}

void udp_start(struct udp_context *udp) {
    int fd;
    int rc;

    fd = socket(udp->local_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        perror("udp: socket");
        exit(1);
    }

    rc = bind(fd, (struct sockaddr *) &udp->local_addr, udp->local_addrlen);
    if (rc < 0) {
        perror("udp: bind");
        exit(1);
    }
    ev_io_set(&udp->io, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &udp->io);
}

void udp_stop(struct udp_context *udp) {
    ev_io_stop(EV_DEFAULT_ &udp->io);
    close(udp->io.fd);
    udp->io.fd = -1;
}

ssize_t udp_sendto(struct udp_context *udp,
                   const uint8_t *msg, socklen_t len,
                   const struct sockaddr *addr, socklen_t addrlen) {
    return sendto(udp->io.fd, msg, len, MSG_DONTWAIT | MSG_NOSIGNAL,
                  addr, addrlen);

}

