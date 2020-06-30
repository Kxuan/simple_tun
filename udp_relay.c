#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <ev.h>
#include <netdb.h>
#include <errno.h>

static ev_io io_udp;
struct client {
    uint8_t id;
    struct sockaddr_storage addr;
    socklen_t addrlen;
};
struct client all_clients[2] = {
        {.id = '0'},
        {.id = '1'},
};
static char buffer[64 * 1024];

static void on_udp_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct client *s, *d;

    while (1) {
        addrlen = sizeof(addr);
        n = recvfrom(io_udp.fd, buffer, sizeof(buffer), MSG_DONTWAIT,
                     (struct sockaddr *) &addr, &addrlen);
        if (n < 1) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("udp: recv");
                exit(1);
            }
            return;
        }

        switch (buffer[0]) {
            case '0':
                s = all_clients + 0;
                d = all_clients + 1;
                break;
            case '1':
                s = all_clients + 1;
                d = all_clients + 0;
                break;
            default:
                fprintf(stderr, "Unexpected client identifier: %02x\n", (int) buffer[0]);
                continue;
        }

        if (s->addrlen != addrlen || memcmp(&addr, &s->addr, addrlen) != 0) {
            char name[100], port[10];
            getnameinfo((const struct sockaddr *) &addr, addrlen,
                        name, sizeof(name),
                        port, sizeof(port), NI_NUMERICHOST);
            fprintf(stderr, "Update client-%c address to %s:%s\n", s->id, name, port);
            s->addrlen = addrlen;
            memcpy(&s->addr, &addr, addrlen);
        }

        if (d->addrlen == 0) {
            fprintf(stderr, "Destination client is unknown.\n");
            continue;
        }

        sendto(io_udp.fd, buffer, n, MSG_DONTWAIT, (struct sockaddr *) &d->addr, d->addrlen);
    }
}

static void udp_wait_client(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    ssize_t n;
    char host[64], service[64];
    int rc;

    n = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) addr, addrlen);
    if (n < 0) {
        perror("recvfrom");
        exit(1);
    }
    rc = getnameinfo(addr, *addrlen, host, sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        fprintf(stderr, "getnameinfo: ");
        fputs(gai_strerror(rc), stderr);
        exit(1);
    }
    fprintf(stderr, "Client %s:%s report\n", host, service);
}

static void udp_start(const char *addr, const char *port) {
    int fd;
    int rc;
    struct addrinfo *ai, req = {};

    rc = getaddrinfo(addr, port, &req, &ai);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: ");
        fputs(gai_strerror(rc), stderr);
        exit(1);
    }

    fd = socket(ai->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    rc = bind(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc < 0) {
        perror("bind");
        exit(1);
    }

    ev_io_init(&io_udp, on_udp_callback, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &io_udp);
}

static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s addr port\n"
                    "\n"
                    "  addr  The local address.\n"
                    "  port  The bind port.\n"
                    "\n"
                    "ISSUES & PR are welcome\n",
            prog_name);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    const char *addr, *port;
    if (argc != 3) {
        usage(argv[0]);
    }
    addr = argv[1];
    port = argv[2];

    udp_start(addr, port);
    ev_run(EV_DEFAULT_ 0);
    return 0;
}