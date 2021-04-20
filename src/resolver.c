/* SPDX-License-Identifier: Apache-2.0 */

#include "compiler.h"
#include "resolver.h"
#include <ares.h>
#include <stdio.h>
#include <stdlib.h>

#define TIMEOUT_RETRY 5

static void stop_io_watchers(struct resolver_context *r) {
    for (int i = 0; i < r->n_io_running; ++i) {
        ev_io_stop(EV_DEFAULT_ r->io + i);
    }
    r->n_io_running = 0;
}

static void update_ares_watchers(struct resolver_context *r) {
    ares_socket_t fds[ARES_GETSOCK_MAXNUM];
    int bitmask;
    int event;

    stop_io_watchers(r);

    bitmask = ares_getsock(r->ares, fds, ARES_GETSOCK_MAXNUM);

    ev_io *w = r->io;
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
        event = 0;
        if (ARES_GETSOCK_READABLE(bitmask, i)) {
            event |= EV_READ;
        }
        if (ARES_GETSOCK_WRITABLE(bitmask, i)) {
            event |= EV_WRITE;
        }
        if (event != 0) {
            ev_io_set(w, fds[i], event);
            ev_io_start(EV_DEFAULT_ w);
            w++;
        } else {
            break;
        }
    }
    r->n_io_running = (int) (w - r->io);
}

static void name_resolved_cb(void *arg,
                             int status,
                             int timeouts,
                             struct ares_addrinfo *res);

static int query_start(struct resolver_context *r) {
    struct ares_addrinfo_hints hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = r->socktype,
        .ai_flags = 0,
        .ai_protocol = 0,
    };

    r->status = RESOLVER_QUERY;

    ev_timer_set(&r->timer, 1, 1);
    ev_timer_start(EV_DEFAULT_ &r->timer);

    ares_getaddrinfo(r->ares, r->host, r->port, &hints, name_resolved_cb, r);
    if (r->status == RESOLVER_QUERY) {
        update_ares_watchers(r);
    }
}

static int query_stop(struct resolver_context *r) {
    r->status = RESOLVER_IDLE;

    ev_timer_stop(EV_DEFAULT_ &r->timer);
    stop_io_watchers(r);
}

void name_resolved_cb(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
    struct resolver_context *r = arg;
    int retry_timeout = TIMEOUT_RETRY;

    query_stop(r);

    if (status != ARES_SUCCESS) {
        fprintf(stderr, "resolver: failed to resolve name, retry in %d seconds. (status=%d)\n", retry_timeout, status);
        goto out_retry;
    }

    if (!res || !res->nodes) {
        fprintf(stderr, "resolver: empty result, retry in %d seconds.\n", retry_timeout);
        goto out_retry;
    }

    struct ares_addrinfo_node *node = res->nodes;

    /**
     * + 1 on ttl to reduce query count.
     *
     * For example, if a DNS record in DNS server will expire in 59.3 seconds, due to TTL field in DNS message is an
     * integer, some DNS servers may round down the TTL to 59 and response to us.
     * If we don't plus 1 second here, and query in 59 seconds later, the DNS server will response TTL = 0 or 1.
     * And this results we have to do the third query in just 1 second later.
     *
     * Simply plus 1 second on ttl, this problem can be resolved.
     */
    retry_timeout = node->ai_ttl + 1;

    if (unlikely(retry_timeout < 1)) {
        /* ai_ttl is defined as a signed integer and there is no any document says ai_ttl can not be negative. */
        retry_timeout = 1;
    }

    if (node->ai_addrlen == r->addrlen && memcmp(node->ai_addr, &r->addr, r->addrlen) == 0) {
        goto out_retry;
    }

    r->addrlen = node->ai_addrlen;
    memcpy(&r->addr, node->ai_addr, r->addrlen);
    r->changed_cb(r, (struct sockaddr *) &r->addr, r->addrlen);

out_retry:
    ev_timer_set(&r->timer, retry_timeout, 0);
    ev_timer_start(EV_DEFAULT_ &r->timer);
    if (res) {
        ares_freeaddrinfo(res);
    }
}

static void io_cb(EV_P_ ev_io *w, int revents) {
    struct resolver_context *r = w->data;
    int rfd = ARES_SOCKET_BAD, wfd = ARES_SOCKET_BAD;

    if (revents & EV_READ) {
        rfd = w->fd;
    }
    if (revents & EV_WRITE) {
        wfd = w->fd;
    }
    ares_process_fd(r->ares, rfd, wfd);
    update_ares_watchers(r);
}

static void timer_cb(EV_P_ ev_timer *w, int revents) {
    struct resolver_context *r = w->data;
    switch (r->status) {
    case RESOLVER_IDLE: {
        query_start(r);
        break;
    }
    case RESOLVER_QUERY: {
        ares_process(r->ares, NULL, NULL);
        if (r->status == RESOLVER_QUERY) {
            update_ares_watchers(r);
        }
        break;
    }
    }
}

void resolver_init(struct resolver_context *r, resolver_changed_fn changed_cb,
                   int sock_type, const char *host, const char *port) {
    r->changed_cb = changed_cb;
    r->host = host;
    r->port = port;
    r->socktype = sock_type;

    ev_timer_init(&r->timer, timer_cb, 0, 0);
    r->timer.data = r;

    for (int i = 0; i < ARES_GETSOCK_MAXNUM; ++i) {
        ev_io_init(r->io + i, io_cb, -1, EV_READ);
        r->io[i].data = r;
    }
    r->n_io_running = 0;

    r->addrlen = 0;

    r->status = RESOLVER_IDLE;
}

int resolver_start(struct resolver_context *r) {
    int rc;

    rc = ares_library_init(ARES_LIB_INIT_ALL);
    if (rc != 0) {
        fprintf(stderr, "ares_library_init: rc = %d\n", rc);
        goto err;
    }

    rc = ares_init(&r->ares);
    if (rc != 0) {
        fprintf(stderr, "ares_init: rc = %d\n", rc);
        goto err_free_ares_library;
    }

    query_start(r);

    return 0;
err_free_ares_library:
    ares_library_cleanup();
err:
    return rc;
}

void resolver_stop(struct resolver_context *r) {
    if (r->ares == NULL) {
        return;
    }
    query_stop(r);
    ares_destroy(r->ares);
    ares_library_cleanup();
}
