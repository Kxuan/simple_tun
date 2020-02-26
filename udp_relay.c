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
static struct sockaddr_storage addr1, addr2;
static socklen_t addr1len, addr2len;
static char buffer[64 * 1024];

static void on_udp_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;
    struct sockaddr_storage src_addr;
    socklen_t src_addrlen, dst_addrlen;
    struct sockaddr *dst_addr;

    while (1) {
        src_addrlen = sizeof(src_addr);
        n = recvfrom(io_udp.fd, buffer, sizeof(buffer), MSG_DONTWAIT,
                     (struct sockaddr *) &src_addr, &src_addrlen);
        if (n < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("udp: recv");
                exit(1);
            }
            return;
        }

        if (src_addrlen == addr1len && memcmp(&src_addr, &addr1, addr1len) == 0) {
            dst_addr = (struct sockaddr *) &addr2;
            dst_addrlen = addr2len;
        } else if (src_addrlen == addr2len && memcmp(&src_addr, &addr2, addr2len) == 0) {
            dst_addr = (struct sockaddr *) &addr1;
            dst_addrlen = addr1len;
        } else {
            return;
        }

        sendto(io_udp.fd, buffer, n, MSG_DONTWAIT, dst_addr, dst_addrlen);
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

    addr1len = sizeof(addr1);
    udp_wait_client(fd, (struct sockaddr *) &addr1, &addr1len);
    do {
        fprintf(stderr, "Waiting for the second client\n");
        addr2len = sizeof(addr2);
        udp_wait_client(fd, (struct sockaddr *) &addr2, &addr2len);
    } while (addr1len == addr2len && memcmp(&addr2, &addr1, addr1len) == 0);

    fprintf(stderr, "Okay, let's relay data.\n");
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