#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "server.h"
#include "client.h"
#define VERSION "1.0.0"
#define DEFAULT_PORT 8443

static void print_usage(void) {
    printf("Droppy v%s - Minimal Encrypted File Transfer\n\n", VERSION);
    printf("Usage:\n");
    printf("  droppy serve [options]             Start server\n");
    printf("  droppy send <host> <file>          Upload file\n");
    printf("  droppy receive <host> <file>       Download file\n");
    printf("  droppy list <host>                 List files\n");
    printf("  droppy hosts                       List servers on local network\n");
    printf("  droppy version                     Show version\n");
    printf("  droppy help                        Show this help\n\n");
    printf("Options:\n");
    printf("  --port <num>       Port (default: %d)\n", DEFAULT_PORT);
    printf("  --dir <path>       Directory (default: current)\n");
    printf("  --cert <file>      Certificate file (default: server.crt)\n");
    printf("  --key <file>       Key file (default: server.key)\n");
    printf("  --verbose          Verbose output\n");
}

typedef struct {
    int port;
    const char *dir;
    const char *cert;
    const char *key;
    int verbose;
} ServeOptions;

int parse_serve_options(int argc, char **argv, ServeOptions *opt) {
    opt->port = DEFAULT_PORT;
    opt->dir = ".";
    opt->cert = "server.crt";
    opt->key = "server.key";
    opt->verbose = 0;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            opt->port = atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--dir") && i + 1 < argc) {
            opt->dir = argv[++i];
        }
        else if (!strcmp(argv[i], "--cert") && i + 1 < argc) {
            opt->cert = argv[++i];
        }
        else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            opt->key = argv[++i];
        }
        else if (!strcmp(argv[i], "--verbose")) {
            opt->verbose = 1;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    /* droppy serve */
    if (!strcmp(argv[1], "serve")) {
        ServeOptions opt;
        if (parse_serve_options(argc, argv, &opt) != 0)
            return 1;

        printf("Starting server on port %d\n", opt.port);
        printf("Dir: %s\nCert: %s\nKey: %s\nVerbose: %d\n",
               opt.dir, opt.cert, opt.key, opt.verbose);
        // start_server(port, dir, cert, key, verbose)
        /* start_server(&opt); */
        return start_server(opt.port, opt.dir, opt.cert, opt.key, opt.verbose);
    }

    /* droppy send <host> <file> */
    if (!strcmp(argv[1], "send")) {
        if (argc < 4) {
            printf("send requires <host> <file>\n");
            return 1;
        }
        const char *host = argv[2];
        const char *file = argv[3];

        printf("Sending %s to %s\n", file, host);
        /* send_file(host, file); */
        return client_send(host, DEFAULT_PORT, file, 0);
    }

    /* droppy list */
    if (!strcmp(argv[1], "list")) {
        if (argc < 3) {
            printf("list requires <host>\n");
            return 1;
        }
        return client_list(argv[2], DEFAULT_PORT, 0);
    }

    /* droppy receive */
    if (!strcmp(argv[1], "receive")) {
        if (argc < 4) {
            printf("receive requires <host> <file>\n");
            return 1;
        }
        return client_receive(argv[2], DEFAULT_PORT, argv[3], 0);
    }

    /* droppy hosts */
    if (!strcmp(argv[1], "hosts")) {
        printf("Scanning local network...\n");
        /* list_hosts(); */
        list_hosts(DEFAULT_PORT, 0);
        return 0;
    }

    /* droppy version */
    if (!strcmp(argv[1], "version")) {
        printf("Droppy v%s\n", VERSION);
        return 0;
    }

    /* droppy help */
    if (!strcmp(argv[1], "help")) {
        print_usage();
        return 0;
    }

    print_usage();
    return 1;
}
