/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SIMPLE_TUN_RESOLVER_H
#define SIMPLE_TUN_RESOLVER_H

#include <sys/socket.h>
#include <ares.h>
#include <ev.h>

struct resolver_context;

typedef void (*resolver_changed_fn)(struct resolver_context *resolver,
                                    const struct sockaddr *addr, socklen_t addrlen);
enum resolver_status {
    /* Resolver is waiting for result expire */
    RESOLVER_IDLE,
    /* Resolver is waiting for result expire */
    RESOLVER_QUERY,
};
struct resolver_context {
    enum resolver_status status;
    resolver_changed_fn changed_cb;
    const char *host, *port;
    int socktype;
    struct sockaddr_storage addr;
    socklen_t addrlen;

    ares_channel ares;
    ev_timer timer;
    int n_io_running;
    ev_io io[ARES_GETSOCK_MAXNUM];
};

void resolver_init(struct resolver_context *r, resolver_changed_fn changed_cb,
                   int sock_type, const char *host, const char *port);

int resolver_start(struct resolver_context *r);

void resolver_stop(struct resolver_context *r);

#endif //SIMPLE_TUN_RESOLVER_H
