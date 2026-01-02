// Created by antonio on 12/29/25.
#include "server.h"
#include "net.h"
#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/error.h>

// TODO: add adderss already used error
// TODO: resolve PORT NUMBER

#ifdef MBEDTLS_USE_PSA_CRYPTO
#include <psa/crypto.h>
#endif

#ifdef _WIN32
    #include <windows.h>
    #define THREAD_RETURN DWORD WINAPI
    #define THREAD_TYPE HANDLE
#else
    #include <pthread.h>
    #define THREAD_RETURN void*
    #define THREAD_TYPE pthread_t
#endif

typedef struct {
    connection_t *conn;
    char dir[1024];
    int verbose;
} client_handler_args_t;

static THREAD_RETURN handle_client(void *arg) {
    client_handler_args_t *args = (client_handler_args_t *)arg;
    connection_t *conn = args->conn;
    unsigned char buf[65536];
    http_request_t req;
    int ret;

    ret = tls_read(conn, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        if (http_parse_request((char *)buf, &req) == 0) {
            http_route_request(conn, &req, args->dir);
        }
    }

    tls_connection_free(conn);
    close_socket(conn->sock);
    free(conn);
    free(args);
    return 0;
}

int start_server(int port, const char *dir,
                 const char *cert_path,
                 const char *key_path,
                 int verbose) {

#ifdef MBEDTLS_USE_PSA_CRYPTO
    psa_crypto_init();
#endif

    if (platform_init() != 0) {
        fprintf(stderr, "Platform init failed\n");
        return 1;
    }

    tls_server_ctx_t tls_ctx;
    const int ret = tls_server_init(&tls_ctx, cert_path, key_path);
    if (ret != 0) {
        char errbuf[256];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "Error: TLS initialization failed: %s\n", errbuf);

        platform_cleanup();
        return 1;
    }

    SOCKET_TYPE listen_sock = create_socket();
    if (listen_sock < 0) {
        fprintf(stderr, "Error: Cannot create socket\n");
        tls_server_free(&tls_ctx);
        platform_cleanup();
        return 1;
    }

    if (bind_socket(listen_sock, port) < 0) {
        fprintf(stderr, "Error: Cannot bind to port %d\n", port);
        close_socket(listen_sock);
        tls_server_free(&tls_ctx);
        platform_cleanup();
        return 1;
    }

    if (listen_socket(listen_sock) < 0) {
        fprintf(stderr, "Error: Cannot listen\n");
        close_socket(listen_sock);
        tls_server_free(&tls_ctx);
        platform_cleanup();
        return 1;
    }

    printf("Droppy server listening on port %d\n", port);
    printf("Serving files from: %s\n", dir);

    while (1) {
        SOCKET_TYPE client_sock = accept_connection(listen_sock);
        if (client_sock < 0) continue;

        connection_t *conn = calloc(1, sizeof(connection_t));
        if (!conn) {
            close_socket(client_sock);
            continue;
        }

        conn->sock = client_sock;
        mbedtls_ssl_init(&conn->ssl);

        if (tls_accept(&tls_ctx, conn) != 0) {
            if (verbose) fprintf(stderr, "TLS handshake failed\n");
            close_socket(client_sock);
            free(conn);
            continue;
        }

        client_handler_args_t *args = malloc(sizeof(client_handler_args_t));
        if (!args) {
            tls_connection_free(conn);
            close_socket(client_sock);
            free(conn);
            continue;
        }

        args->conn = conn;
        strncpy(args->dir, dir, sizeof(args->dir) - 1);
        args->dir[sizeof(args->dir) - 1] = '\0';
        args->verbose = verbose;

#ifdef _WIN32
        CreateThread(NULL, 0, handle_client, args, 0, NULL);
#else
        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, args);
        pthread_detach(thread);
#endif
    }

    close_socket(listen_sock);
    tls_server_free(&tls_ctx);
    platform_cleanup();
    return 0;
}
