#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_HEADER 8192

static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 500: return "Internal Server Error";
        default:  return "Error";
    }
}

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1])) && ((b = src[2])) &&
            isxdigit(a) && isxdigit(b)) {

            a = (char)(isdigit(a) ? a - '0' : tolower(a) - 'a' + 10);
            b = (char)(isdigit(b) ? b - '0' : tolower(b) - 'a' + 10);
            *dst++ = (char)(16 * a + b);
            src += 3;
            } else if (*src == '+') {
                *dst++ = ' ';
                src++;
            } else {
                *dst++ = *src++;
            }
    }
    *dst = '\0';
}

long long http_parse_content_length(const char *headers) {
    const char *p = strcasestr(headers, "Content-Length:");
    if (!p) return -1;
    p += 15;
    while (*p == ' ') p++;
    return atoll(p);
}

int http_parse_request(const char *raw, http_request_t *req) {
    if (!raw || !req) return -1;

    memset(req, 0, sizeof(*req));

    char method[16], path[1024];
    if (sscanf(raw, "%15s %1023s", method, path) != 2)
        return -1;

    strncpy(req->method, method, sizeof(req->method) - 1);
    strncpy(req->path, path, sizeof(req->path) - 1);

    const char *hdrs = strstr(raw, "\r\n");
    if (!hdrs) return -1;

    req->content_length = http_parse_content_length(raw);
    return 0;
}

void http_send_response(connection_t *conn, int code, const char *status,
                        const char *content_type, const char *body, size_t len) {

    char header[1024];
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %zu\r\n"
        "Content-Type: %s\r\n"
        "Connection: close\r\n\r\n",
        code, status, len, content_type);

    tls_write(conn, (unsigned char *)header, n);
    if (body && len)
        tls_write(conn, (unsigned char *)body, len);
}

void http_send_file_response(connection_t *conn, const char *filename, long long size) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        const char *msg = "File not found";
        http_send_response(conn, 404, status_text(404), "text/plain", msg, strlen(msg));
        return;
    }

    char hdr[1024];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %lld\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: close\r\n\r\n", size);

    tls_write(conn, (unsigned char *)hdr, n);

    unsigned char buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
        tls_write(conn, buf, r);

    fclose(f);
}

void http_route_request(connection_t *conn, const http_request_t *req, const char *dir) {
    char path[2048];
    char decoded[1024];

    url_decode(decoded, req->path);

    // prevent directory traversal
    if (strstr(decoded, "..")) {
        const char *msg = "Forbidden";
        http_send_response(conn, 403, status_text(403), "text/plain", msg, strlen(msg));
        return;
    }

    snprintf(path, sizeof(path), "%s/%s", dir, decoded[0] == '/' ? decoded + 1 : decoded);

    if (!strcmp(req->method, "GET")) {
        FILE *f = fopen(path, "rb");
        if (!f) {
            const char *msg = "Not found";
            http_send_response(conn, 404, status_text(404), "text/plain", msg, strlen(msg));
            return;
        }

        fseek(f, 0, SEEK_END);
        long long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        fclose(f);

        http_send_file_response(conn, path, size);
        return;
    }

    const char *msg = "Bad request";
    http_send_response(conn, 400, status_text(400), "text/plain", msg, strlen(msg));
}