#include "client.h"
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

static int get_local_base(char *base) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return -1;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        const char *ip = inet_ntoa(sa->sin_addr);

        if (strncmp(ip, "127.", 4) != 0) {
            strncpy(base, ip, 32);
            char *last = strrchr(base, '.');
            if (last) *(last + 1) = '\0';
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

int client_send(const char *host, int port, const char *filepath, int verbose) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    SOCKET_TYPE sock = create_socket();
    if (connect_socket(sock, host, port) != 0) return -1;

    connection_t conn = {0};
    conn.sock = sock;
    strncpy(conn.hostname, host, sizeof(conn.hostname)-1);

    if (tls_client_init(&conn) != 0) return -1;
    if (tls_connect(&conn) != 0) return -1;

    char hdr[1024];
    snprintf(hdr, sizeof(hdr),
        "POST /upload/%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: %lld\r\n"
        "Connection: close\r\n\r\n",
        strrchr(filepath,'/') ? strrchr(filepath,'/')+1 : filepath,
        host, size);

    tls_write(&conn, (unsigned char*)hdr, strlen(hdr));

    unsigned char buf[4096];
    size_t r;
    while ((r = fread(buf,1,sizeof(buf),f)) > 0)
        tls_write(&conn, buf, r);

    fclose(f);
    tls_connection_free(&conn);
    close_socket(sock);
    return 0;
}

int client_list(const char *host, int port, int verbose) {
    SOCKET_TYPE sock = create_socket();
    if (connect_socket(sock, host, port) != 0) return -1;

    connection_t conn = {0};
    conn.sock = sock;
    strncpy(conn.hostname, host, sizeof(conn.hostname)-1);

    if (tls_client_init(&conn) != 0) return -1;
    if (tls_connect(&conn) != 0) return -1;

    const char *req =
        "GET /list HTTP/1.1\r\n"
        "Connection: close\r\n\r\n";

    tls_write(&conn, (unsigned char*)req, strlen(req));

    unsigned char buf[4096];
    int r;
    while ((r = tls_read(&conn, buf, sizeof(buf)-1)) > 0) {
        buf[r] = 0;
        printf("%s", buf);
    }

    tls_connection_free(&conn);
    close_socket(sock);
    return 0;
}

int client_receive(const char *host, int port, const char *filename, int verbose) {
    SOCKET_TYPE sock = create_socket();
    if (connect_socket(sock, host, port) != 0) return -1;

    connection_t conn = {0};
    conn.sock = sock;
    strncpy(conn.hostname, host, sizeof(conn.hostname)-1);

    if (tls_client_init(&conn) != 0) return -1;
    if (tls_connect(&conn) != 0) return -1;

    char req[512];
    snprintf(req, sizeof(req),
        "GET /%s HTTP/1.1\r\nConnection: close\r\n\r\n", filename);

    tls_write(&conn, (unsigned char*)req, strlen(req));

    FILE *f = fopen(filename, "wb");
    if (!f) return -1;

    unsigned char buf[4096];
    int r;
    while ((r = tls_read(&conn, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, r, f);

    fclose(f);
    tls_connection_free(&conn);
    close_socket(sock);
    return 0;
}

static int probe_host(const char *ip, int port) {
    SOCKET_TYPE sock = create_socket();
    if (connect_socket(sock, ip, port) != 0) {
        close_socket(sock);
        return 0;
    }

    connection_t conn = {0};
    conn.sock = sock;
    strncpy(conn.hostname, ip, sizeof(conn.hostname)-1);

    if (tls_client_init_discovery(&conn) != 0) { close_socket(sock); return 0; }
    if (mbedtls_ssl_handshake(&conn.ssl) != 0)     { close_socket(sock); return 0; }

    tls_connection_free(&conn);
    close_socket(sock);
    return 1;
}

void list_hosts(int port, int verbose) {
    char ip[32];
    char base[32];
    if (get_local_base(base) != 0) {
        printf("Could not detect local subnet\n");
        return;
    }
    printf("Scanning local network %s0/24 ...\n", base);

    for (int i = 1; i < 255; i++) {
        snprintf(ip, sizeof(ip), "%s%d", base, i);

        if (verbose)
            printf("Probing %s...\n", ip);

        if (probe_host(ip, port)) {
            printf("Droppy server found at %s\n", ip);
        }
    }
}