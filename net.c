// network utilities
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <mbedtls/error.h>
#include "mbedtls/net_sockets.h"

#ifdef _WIN32
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#include <netdb.h>
#endif


static const int STRONG_CIPHERSUITES[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    0
};

static int tls_would_block(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

// Socket BIO callbacks for mbedTLS
static int tls_send_cb(void *ctx, const unsigned char *buf, size_t len) {
    SOCKET_TYPE sock = *(SOCKET_TYPE *)ctx;
#ifdef _WIN32
    int ret = send(sock, (const char *)buf, (int)len, 0);
    if (ret == SOCKET_ERROR) {
        if (tls_would_block()) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
#else
    ssize_t ret = send(sock, buf, len, 0);
    if (ret < 0) {
        if (tls_would_block()) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return (int)ret;
#endif
}

static int tls_recv_cb(void *ctx, unsigned char *buf, size_t len) {
    SOCKET_TYPE sock = *(SOCKET_TYPE *)ctx;
#ifdef _WIN32
    int ret = recv(sock, (char *)buf, (int)len, 0);
    if (ret == 0) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    if (ret == SOCKET_ERROR) {
        if (tls_would_block()) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;
#else
    ssize_t ret = recv(sock, buf, len, 0);
    if (ret == 0) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    if (ret < 0) {
        if (tls_would_block()) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return (int)ret;
#endif
}

// Platform
int platform_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

void platform_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// socket functions
SOCKET_TYPE create_socket(void) {
    return socket(AF_INET, SOCK_STREAM, 0);
}

int bind_socket(SOCKET_TYPE sock, int port) {
    struct sockaddr_in addr;
    int opt = 1;

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    return bind(sock, (struct sockaddr *)&addr, sizeof(addr));
}

int listen_socket(SOCKET_TYPE sock) {
    return listen(sock, 5);
}

SOCKET_TYPE accept_connection(SOCKET_TYPE sock) {
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    return accept(sock, (struct sockaddr *)&client_addr, &len);
}

int connect_socket(SOCKET_TYPE sock, const char *host, int port) {
    struct sockaddr_in addr;
    struct hostent *he = gethostbyname(host);

    if (!he) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    return connect(sock, (struct sockaddr *)&addr, sizeof(addr));
}

void close_socket(SOCKET_TYPE sock) {
    close(sock);
}

int tls_server_init(tls_server_ctx_t *ctx, const char *cert_path, const char *key_path) {
    if (!ctx || !cert_path || !key_path) return -1;

    memset(ctx, 0, sizeof(*ctx));

    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_x509_crt_init(&ctx->cert);
    mbedtls_pk_init(&ctx->pkey);

    const char *pers = "droppy_server";
    int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
                                    &ctx->entropy,
                                    (const unsigned char *)pers,
                                    strlen(pers));
    if (ret != 0) return ret;

    if ((ret = mbedtls_x509_crt_parse_file(&ctx->cert, cert_path)) != 0)
        return ret;

    if ((ret = mbedtls_pk_parse_keyfile(&ctx->pkey, key_path, NULL,
                                        mbedtls_ctr_drbg_random,
                                        &ctx->ctr_drbg)) != 0)
        return ret;

    if ((ret = mbedtls_ssl_config_defaults(&ctx->conf,
            MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
        return ret;

    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    if ((ret = mbedtls_ssl_conf_own_cert(&ctx->conf,
                                        &ctx->cert,
                                        &ctx->pkey)) != 0)
        return ret;

    return 0;
}

void tls_server_free(tls_server_ctx_t *ctx) {
    if (!ctx) return;

    mbedtls_pk_free(&ctx->pkey);
    mbedtls_x509_crt_free(&ctx->cert);
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);

    memset(ctx, 0, sizeof(*ctx));
}

int tls_accept(tls_server_ctx_t *ctx, connection_t *conn) {
    if (!ctx || !conn) return -1;

    // Initialize per-connection pieces
    mbedtls_ssl_init(&conn->ssl);
    // conn->sock must already be a valid-accepted socket
    int ret = mbedtls_ssl_setup(&conn->ssl, &ctx->conf);
    if (ret != 0) return ret;

    mbedtls_ssl_set_bio(&conn->ssl, &conn->sock, tls_send_cb, tls_recv_cb, NULL);

    // Handshake loop
    while ((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        return ret;
    }

    return 0;
}

int tls_client_init(connection_t *conn) {
    if (!conn) return -1;

    // Do not wipe conn->sock / hostname
    mbedtls_ssl_init(&conn->ssl);
    mbedtls_ssl_config_init(&conn->conf);
    mbedtls_entropy_init(&conn->entropy);
    mbedtls_ctr_drbg_init(&conn->ctr_drbg);
    mbedtls_x509_crt_init(&conn->ca);

    const char *pers = "tls_client";
    int ret = mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func, &conn->entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) return ret;

    // Load CA bundle (required for safe server verification)
    const char *ca_path = getenv("TLS_CA_BUNDLE");
    if (!ca_path) {
        // No CA => cannot verify safely
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }
    ret = mbedtls_x509_crt_parse_file(&conn->ca, ca_path);
    if (ret != 0) return ret;

    ret = mbedtls_ssl_config_defaults(&conn->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) return ret;

    mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
    mbedtls_ssl_conf_min_version(&conn->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.2
    mbedtls_ssl_conf_ciphersuites(&conn->conf, STRONG_CIPHERSUITES);

#ifdef MBEDTLS_SSL_RENEGOTIATION
    mbedtls_ssl_conf_renegotiation(&conn->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

    // Require verification
    mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->ca, NULL);

    ret = mbedtls_ssl_setup(&conn->ssl, &conn->conf);
    if (ret != 0) return ret;

    mbedtls_ssl_set_bio(&conn->ssl, &conn->sock, tls_send_cb, tls_recv_cb, NULL);

    return 0;
}

int tls_connect(connection_t *conn) {
    if (!conn) return -1;

    // Hostname is required for SNI + verification
    if (conn->hostname[0] == '\0') {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    int ret = mbedtls_ssl_set_hostname(&conn->ssl, conn->hostname);
    if (ret != 0) return ret;

    while ((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        return ret;
    }

    // Verify server certificate
    uint32_t flags = mbedtls_ssl_get_verify_result(&conn->ssl);
    if (flags != 0) {
        // Verification failed
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    }

    return 0;
}

void tls_connection_free(connection_t *conn) {
    if (!conn) return;

    // Best-effort close_notify
    if (conn->ssl.private_state != MBEDTLS_SSL_HELLO_REQUEST) {
        (void)mbedtls_ssl_close_notify(&conn->ssl);
    }

    mbedtls_ssl_free(&conn->ssl);
    mbedtls_x509_crt_free(&conn->ca);
    mbedtls_ssl_config_free(&conn->conf);
    mbedtls_ctr_drbg_free(&conn->ctr_drbg);
    mbedtls_entropy_free(&conn->entropy);

    // You still own/close conn->sock separately if you want
    // close_socket(conn->sock);

    // Keep hostname/sock as-is unless you want to clear
}

int tls_read(connection_t *conn, unsigned char *buf, size_t len) {
    if (!conn || !buf || len == 0) return -1;

    int ret;
    while ((ret = mbedtls_ssl_read(&conn->ssl, buf, len)) < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
        return ret;
    }
    return ret;
}

int tls_write(connection_t *conn, const unsigned char *buf, size_t len) {
    if (!conn || !buf || len == 0) return -1;

    size_t off = 0;
    while (off < len) {
        int ret = mbedtls_ssl_write(&conn->ssl, buf + off, len - off);
        if (ret > 0) {
            off += (size_t)ret;
            continue;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        return ret;
    }
    return (int)off;
}

int tls_client_init_discovery(connection_t *conn) {
    mbedtls_ssl_init(&conn->ssl);
    mbedtls_ssl_config_init(&conn->conf);
    mbedtls_entropy_init(&conn->entropy);
    mbedtls_ctr_drbg_init(&conn->ctr_drbg);

    const char *pers = "droppy_discovery";
    mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func, &conn->entropy,
                          (const unsigned char *)pers, strlen(pers));

    mbedtls_ssl_config_defaults(&conn->conf,
        MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
    mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_setup(&conn->ssl, &conn->conf);
    mbedtls_ssl_set_bio(&conn->ssl, &conn->sock, tls_send_cb, tls_recv_cb, NULL);
    return 0;
}