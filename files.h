#ifndef FILES_H
#define FILES_H

#include "net.h"
#include "http.h"

// Handlers
void handle_upload(connection_t *conn, const char *filename, long long content_len, const char *dir);
void handle_download(connection_t *conn, const char *filename, const char *dir);
void handle_list(connection_t *conn, const char *dir);

// Validation
int safe_filename(const char *name);

#endif