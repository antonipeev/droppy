#ifndef NET_H
#define NET_H

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define SOCKET_TYPE SOCKET
#else
    #define SOCKET_TYPE int
#endif

#include <stddef.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

typedef struct {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
} tls_server_ctx_t;

typedef struct {
    // Socket
    SOCKET_TYPE sock;

    // TLS session + per-connection config & RNG
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // CA chain for verifying the server (client side)
    mbedtls_x509_crt ca;

    // Hostname for SNI + verification (client side)
    char hostname[256];
} connection_t;

// Platform
int platform_init(void);
void platform_cleanup(void);

// Sockets
SOCKET_TYPE create_socket(void);
int bind_socket(SOCKET_TYPE sock, int port);
int listen_socket(SOCKET_TYPE sock);
SOCKET_TYPE accept_connection(SOCKET_TYPE sock);
int connect_socket(SOCKET_TYPE sock, const char *host, int port);
void close_socket(SOCKET_TYPE sock);

// TLS Server
int tls_server_init(tls_server_ctx_t *ctx, const char *cert_path, const char *key_path);
void tls_server_free(tls_server_ctx_t *ctx);
int tls_accept(tls_server_ctx_t *ctx, connection_t *conn);

// TLS Client
int tls_client_init(connection_t *conn);
int tls_connect(connection_t *conn);
void tls_connection_free(connection_t *conn);

// TLS I/O
int tls_read(connection_t *conn, unsigned char *buf, size_t len);
int tls_write(connection_t *conn, const unsigned char *buf, size_t len);

int tls_client_init_discovery(connection_t *conn);
#endif
