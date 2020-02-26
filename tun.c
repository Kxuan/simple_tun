#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <ev.h>
#include <netdb.h>
#include <errno.h>

static ev_io io_tun, io_udp;
static char buffer[64 * 1024];

static void on_tun_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;

    n = read(io_tun.fd, buffer, sizeof(buffer));
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("tun: read");
            exit(1);
        }
        return;
    }
    send(io_udp.fd, buffer, n, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void on_udp_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;

    n = recv(io_udp.fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("udp: recv");
            exit(1);
        }
        return;
    }
    write(io_tun.fd, buffer, n);
}

static void tun_start(void) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0) {
        perror("/dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        perror("TUNSETIFF");
        exit(1);
    }

    ev_io_init(&io_tun, on_tun_callback, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &io_tun);
}

static void udp_start(int listen_mode, const char *addr, const char *port) {
    int fd;
    int rc;
    struct addrinfo *ai, req = {};

    rc = getaddrinfo(addr, port, &req, &ai);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: ");
        fputs(gai_strerror(rc), stderr);
        exit(1);
    }

    fd = socket(ai->ai_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    if (listen_mode) {
        rc = bind(fd, ai->ai_addr, ai->ai_addrlen);
    } else {
        rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    }
    if (rc < 0) {
        perror(listen_mode ? "bind" : "connect");
        exit(1);
    }
    ev_io_init(&io_udp, on_udp_callback, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &io_udp);
}

static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [-l] addr port\n"
                    "\n"
                    "Options:\n"
                    "   -l   Listen mode. (The default is connect mode)\n"
                    "\n"
                    "  addr  The local address in listen mode or the remote address in connect mode.\n"
                    "  port  The bind port in listen mode or the remote port in connect mode.\n"
                    "\n"
                    "ISSUES & PR are welcome\n",
            prog_name);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    int opt;
    int listen_mode = 0;
    const char *addr, *port;
    while ((opt = getopt(argc, argv, "l")) != -1) {
        switch (opt) {
            case 'l':
                listen_mode = 1;
                break;
            default: /* '?' */
                usage(argv[0]);
        }
    }
    if (optind + 2 != argc) {
        usage(argv[0]);
    }
    addr = argv[optind];
    port = argv[optind + 1];

    tun_start();
    udp_start(listen_mode, addr, port);
    ev_run(EV_DEFAULT_ 0);
    return 0;
}