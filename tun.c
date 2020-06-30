#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <ev.h>
#include <netdb.h>
#include <errno.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define PROGNAME "Simple TUN/TAP"
static ev_io io_tun, io_udp;
static uint8_t buffer_plaintext[64 * 1024], buffer_ciphertext[1 + 64 * 1024 + 16];
static mbedtls_gcm_context aes_gcm;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static struct sockaddr_storage peer_addr;
static socklen_t peer_addrlen = 0;
static uint8_t relay_client_id = 0;

static void mbedtls_fail(const char *func, int rc) {
    char buf[100];
    mbedtls_strerror(rc, buf, sizeof(buf));
    fprintf(stderr, "%s: %s\n", func, buf);
    exit(1);
}

static void crypto_init(uint8_t key[16]) {
    int rc;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if ((rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, PROGNAME, sizeof(PROGNAME))) != 0) {
        mbedtls_fail("mbedtls_ctr_drbg_seed", rc);
    }

    mbedtls_gcm_init(&aes_gcm);
    if ((rc = mbedtls_gcm_setkey(&aes_gcm, MBEDTLS_CIPHER_ID_AES, key, 128)) != 0) {
        mbedtls_fail("mbedtls_gcm_setkey", rc);
    }
}

static void crypto_encrypt(
        uint8_t *out_buf, size_t *olen,
        const uint8_t *plaintext, size_t len) {
    uint8_t *out_iv = out_buf,
            *out_ciphertext = out_iv + 12,
            *out_tag = out_ciphertext + len;
    int rc;
    if ((rc = mbedtls_ctr_drbg_random(&ctr_drbg, out_iv, 12)) != 0) {
        mbedtls_fail("mbedtls_ctr_drbg_random", rc);
    }

    rc = mbedtls_gcm_crypt_and_tag(&aes_gcm, MBEDTLS_GCM_ENCRYPT, len,
                                   out_iv, 12,
                                   NULL, 0, plaintext,
                                   out_ciphertext,
                                   4, out_tag);
    if (rc != 0) {
        mbedtls_fail("mbedtls_gcm_crypt_and_tag", rc);
    }
    *olen = 12 + len + 4;
}

static int crypto_decrypt(
        uint8_t *out_buf, size_t *olen,
        const uint8_t *ciphertext, size_t len) {

    if (len < 12 + 4) {
        return -1;
    }

    const uint8_t *in_iv = ciphertext,
            *in_ciphertext = in_iv + 12,
            *in_tag = ciphertext + (len - 4);
    int rc;

    rc = mbedtls_gcm_auth_decrypt(&aes_gcm,
                                  in_tag - in_ciphertext,
                                  in_iv, 12,
                                  NULL, 0,
                                  in_tag, 4,
                                  in_ciphertext, out_buf);
    if (rc != 0) {
        return rc;
    }
    *olen = in_tag - in_ciphertext;
    return rc;
}

static void on_tun_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;

    if (peer_addrlen == 0) {
        return;
    }
    n = read(io_tun.fd, buffer_plaintext, sizeof(buffer_plaintext));
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("tun: read");
            exit(1);
        }
        return;
    }
    size_t new_len;
    crypto_encrypt(buffer_ciphertext + 1, &new_len, buffer_plaintext, n);
    buffer_ciphertext[0] = relay_client_id;

    sendto(io_udp.fd, buffer_ciphertext, new_len + 1, MSG_DONTWAIT | MSG_NOSIGNAL,
           (struct sockaddr *) &peer_addr, peer_addrlen);
}

static void on_udp_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(&addr);

    n = recvfrom(io_udp.fd, buffer_ciphertext, sizeof(buffer_ciphertext), MSG_DONTWAIT,
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
    size_t new_len;
    int rc = crypto_decrypt(buffer_plaintext, &new_len, buffer_ciphertext + 1, n - 1);
    if (rc != 0) {
        return;
    }
    if (peer_addrlen == 0) {
        peer_addrlen = addrlen;
        memcpy(&peer_addr, &addr, addrlen);
        fprintf(stderr, "Peer incoming\n");
    }
    write(io_tun.fd, buffer_plaintext, new_len);
}

static void tun_start(int is_tun) {
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
    ifr.ifr_flags = (is_tun ? IFF_TUN : IFF_TAP) | IFF_NO_PI;

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
        if (rc < 0) {
            perror(listen_mode ? "bind" : "connect");
            exit(1);
        }
    } else {
        peer_addrlen = ai->ai_addrlen;
        memcpy(&peer_addr, ai->ai_addr, ai->ai_addrlen);
    }
    ev_io_init(&io_udp, on_udp_callback, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &io_udp);
}

static void kdf_password_to_key(uint8_t *out, size_t olen, const char *password, size_t pwlen) {
    int rc;
    int err;

    rc = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                      password, strlen(password),
                      PROGNAME, sizeof(PROGNAME),
                      out, olen);
    if (rc != 0) {
        mbedtls_fail("mbedtls_hkdf", rc);
    }
}

/**
 * random key
 *
 * @param out
 * @param olen
 */
static void gen_random_key(uint8_t *out, size_t olen) {
    int rc;
    int pwlen = olen * 8 / 6 + 1;
    uint8_t password[pwlen];
    static const char password_chars[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if ((rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, PROGNAME, sizeof(PROGNAME))) != 0) {
        mbedtls_fail("mbedtls_ctr_drbg_seed", rc);
    }
    if ((rc = mbedtls_ctr_drbg_random(&ctr_drbg, password, pwlen)) != 0) {
        mbedtls_fail("mbedtls_ctr_drbg_random", rc);
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    for (size_t i = 0; i < pwlen; ++i) {
        password[i] = password_chars[password[i] % 64];
    }

    fprintf(stderr, "Random password: %.*s\n", pwlen, password);
    kdf_password_to_key(out, olen, password, pwlen);
}

static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [-lu] [-s key] [-R 0|1] addr port\n"
                    "\n"
                    "Options:\n"
                    "   -l   Listen mode. (The default is connect mode)\n"
                    "   -u   TUN device. (The default is TAP device)\n"
                    "   -s secret\n"
                    "        Specify the AES key. (The default is a random key)\n"
                    "   -R 0|1\n"
                    "        relay traffic as peer1 or peer2.\n"
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
    int is_tun = 0;
    const char *addr, *port;
    int random_key = 1;
    uint8_t key[16];

    while ((opt = getopt(argc, argv, "lus:R:")) != -1) {
        switch (opt) {
            case 'l':
                listen_mode = 1;
                break;
            case 'u':
                is_tun = 1;
                break;
            case 's':
                kdf_password_to_key(key, sizeof(key), optarg, strlen(optarg));
                random_key = 0;
                break;
            case 'R':
                relay_client_id = optarg[0];
                break;
            default: /* '?' */
                usage(argv[0]);
        }
    }
    if (optind + 2 != argc) {
        usage(argv[0]);
    }
    if (random_key) {
        gen_random_key(key, sizeof(key));
    }
    crypto_init(key);

    addr = argv[optind];
    port = argv[optind + 1];

    tun_start(is_tun);
    udp_start(listen_mode, addr, port);
    ev_run(EV_DEFAULT_ 0);
    return 0;
}