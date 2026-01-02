#ifndef CLIENT_H
#define CLIENT_H

int client_send(const char *host, int port, const char *filepath, int verbose);
int client_list(const char *host, int port, int verbose);
int client_receive(const char *host, int port, const char *filename, int verbose);
void list_hosts(int port, int verbose);
#endif