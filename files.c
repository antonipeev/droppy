#include "files.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

int safe_filename(const char *name) {
    if (!name || !*name) return 0;
    for (const char *p = name; *p; p++)
        if (!isalnum(*p) && *p!='.' && *p!='_' && *p!='-') return 0;
    return 1;
}

void handle_upload(connection_t *conn, const char *filename, long long len, const char *dir) {
    if (!safe_filename(filename)) return;

    char path[1024];
    snprintf(path,sizeof(path),"%s/%s",dir,filename);

    FILE *f = fopen(path,"wb");
    if (!f) return;

    unsigned char buf[4096];
    long long remaining = len;
    while (remaining > 0) {
        int r = tls_read(conn, buf, remaining > 4096 ? 4096 : remaining);
        if (r <= 0) break;
        fwrite(buf,1,r,f);
        remaining -= r;
    }
    fclose(f);
}

void handle_download(connection_t *conn, const char *filename, const char *dir) {
    if (!safe_filename(filename)) return;

    char path[1024];
    snprintf(path,sizeof(path),"%s/%s",dir,filename);

    FILE *f = fopen(path,"rb");
    if (!f) return;

    fseek(f,0,SEEK_END);
    long long size = ftell(f);
    fseek(f,0,SEEK_SET);

    http_send_file_response(conn,path,size);
    fclose(f);
}

void handle_list(connection_t *conn, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;

    char buf[8192]="";
    struct dirent *e;
    while ((e = readdir(d)))
        if (safe_filename(e->d_name))
            strcat(buf,e->d_name), strcat(buf,"\n");

    closedir(d);
    http_send_response(conn,200,"OK","text/plain",buf,strlen(buf));
}