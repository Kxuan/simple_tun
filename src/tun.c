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
#define PROTOCOL_VERSION 1
#define MTU 1450
#define TAG_LEN 16
#define IV_LEN 12
static ev_io io_tun, io_udp;

struct buffer {
    uint8_t *p;
    uint8_t data[MTU];
};

static struct buffer out_buf;
static ev_idle out_idle;
static mbedtls_gcm_context encrypt_cipher, decrypt_cipher;
static uint8_t raw_buf[64 * 1024];
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static struct sockaddr_storage peer_addr;
static socklen_t peer_addrlen = 0;
static uint8_t relay_client_id = 0;

static void buffer_reset(struct buffer *buf) {
    buf->p = buf->data;
}

static void *buffer_push(struct buffer *buf, size_t size) {

    void *p = buf->p;
    buf->p += size;
    return p;
}

static size_t buffer_remains(struct buffer *buf) {
    return sizeof(buf->data) - (buf->p - buf->data);
}

static size_t buffer_len(struct buffer *buf) {
    return buf->p - buf->data;
}

__attribute__((noreturn))
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

    mbedtls_gcm_init(&encrypt_cipher);
    mbedtls_gcm_init(&decrypt_cipher);
    if ((rc = mbedtls_gcm_setkey(&encrypt_cipher, MBEDTLS_CIPHER_ID_AES, key, 128)) != 0) {
        mbedtls_fail("mbedtls_gcm_setkey", rc);
    }
    if ((rc = mbedtls_gcm_setkey(&decrypt_cipher, MBEDTLS_CIPHER_ID_AES, key, 128)) != 0) {
        mbedtls_fail("mbedtls_gcm_setkey", rc);
    }
}

static int crypto_decrypt(
    uint8_t *out, size_t *olen,
    const uint8_t *ciphertext, size_t len) {

    if (len < IV_LEN + TAG_LEN) {
        return -1;
    }

    const uint8_t *in_aad = ciphertext,
        *in_iv = ciphertext + 1,
        *in_ciphertext = in_iv + IV_LEN,
        *in_tag = ciphertext + (len - 4);

    int rc;

    rc = mbedtls_gcm_auth_decrypt(&decrypt_cipher,
                                  in_tag - in_ciphertext,
                                  in_iv, IV_LEN,
                                  in_aad, 1,
                                  in_tag, TAG_LEN,
                                  in_ciphertext, out);
    if (rc != 0) {
        return rc;
    }
    *olen = in_tag - in_ciphertext;
    return rc;
}

static void out_reset_buffer(struct buffer *buf) {
    int rc;

    buffer_reset(buf);
    uint8_t *flags = buffer_push(buf, 1);
    *flags |= relay_client_id == 0;
    uint8_t *iv = buffer_push(buf, 12);
    if ((rc = mbedtls_ctr_drbg_random(&ctr_drbg, iv, 12)) != 0) {
        mbedtls_fail("mbedtls_ctr_drbg_random", rc);
    }
    if ((rc = mbedtls_gcm_starts(&encrypt_cipher, MBEDTLS_ENCRYPT, iv, 12, flags, 1)) != 0) {
        mbedtls_fail("mbedtls_gcm_starts", rc);
    }
}

static void out_flush(struct buffer *buf) {
    uint8_t *tag = buffer_push(buf, TAG_LEN);
    int rc;
    rc = mbedtls_gcm_finish(&encrypt_cipher, tag, TAG_LEN);
    if (rc != 0) {
        mbedtls_fail("mbedtls_gcm_finish", rc);
    }

    sendto(io_udp.fd, buf->data, buffer_len(buf), MSG_DONTWAIT | MSG_NOSIGNAL,
           (struct sockaddr *) &peer_addr, peer_addrlen);

    out_reset_buffer(buf);
}

static void out_push_packet(struct buffer *buf, const void *pkt, size_t pkt_len) {
    if (buffer_remains(buf) < sizeof(uint16_t) + pkt_len + TAG_LEN) {
        out_flush(buf);
    }

    uint8_t *len = buffer_push(buf, sizeof(uint16_t));
    len[0] = (pkt_len >> 8) & 0xff;
    len[1] = pkt_len & 0xff;
    void *ct = buffer_push(buf, pkt_len);
    int rc;
    if ((rc = mbedtls_gcm_update(&encrypt_cipher, pkt_len, pkt, ct)) != 0) {
        mbedtls_fail("mbedtls_gcm_update", rc);
    }
    ev_idle_start(EV_DEFAULT_ &out_idle);
}

static void on_out_idle(EV_P_ ev_idle *w, int revents) {
    ev_idle_stop(EV_A_ w);
    out_flush(&out_buf);
}

static void out_init() {
    out_reset_buffer(&out_buf);
    ev_idle_init(&out_idle, on_out_idle);
}

static void on_tun_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;

    if (peer_addrlen == 0) {
        return;
    }
    n = read(io_tun.fd, raw_buf, sizeof(raw_buf));
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("tun: read");
            exit(1);
        }
        return;
    }
    out_push_packet(&out_buf, raw_buf, n);
}

static void on_udp_callback(EV_P_ ev_io *w, int revents) {
    ssize_t n;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(&addr);

    n = recvfrom(io_udp.fd, raw_buf, sizeof(raw_buf), MSG_DONTWAIT,
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
    int rc = crypto_decrypt(raw_buf, &new_len, raw_buf, n);
    if (rc != 0) {
        return;
    }
    if (peer_addrlen == 0) {
        peer_addrlen = addrlen;
        memcpy(&peer_addr, &addr, addrlen);
        fprintf(stderr, "Peer incoming\n");
    }
    uint8_t *p = raw_buf;
    size_t remains = new_len;
    while (remains > sizeof(uint16_t)) {
        uint16_t len = ((uint16_t) p[0] << 8) | p[1];
        p += 2;
        remains -= 2;

        if (len > remains) {
            return;
        }
        write(io_tun.fd, p, len);
    }
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

    out_init();
    tun_start(is_tun);
    udp_start(listen_mode, addr, port);
    ev_run(EV_DEFAULT_ 0);
    return 0;
}