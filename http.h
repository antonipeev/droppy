#ifndef HTTP_H
#define HTTP_H

#include "net.h"

typedef struct {
    char method[16];
    char path[1024];
    long long content_length;
} http_request_t;

// Parsing
int http_parse_request(const char *raw, http_request_t *req);
long long http_parse_content_length(const char *headers);

// Response
void http_send_response(connection_t *conn, int code, const char *status,
                       const char *content_type, const char *body, size_t len);
void http_send_file_response(connection_t *conn, const char *filename, long long size);

// Routing
void http_route_request(connection_t *conn, const http_request_t *req, const char *dir);

// Utilities
void url_decode(char *dst, const char *src);

#endif