#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sandbox.h"
#include "paths.h"
#include "policy.h"
#include "log.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <command> [args...]\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  create <name> [--profile <profile>]\n");
    fprintf(stderr, "  enter <name>\n");
    fprintf(stderr, "  run <name> <command> [args...]\n");
    fprintf(stderr, "  list\n");
    fprintf(stderr, "  info <name>\n");
    fprintf(stderr, "  destroy <name>\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "create") == 0) {
        return cmd_create(argc - 1, argv + 1);
    } else if (strcmp(cmd, "enter") == 0) {
        return cmd_enter(argc - 1, argv + 1);
    } else if (strcmp(cmd, "run") == 0) {
        return cmd_run(argc - 1, argv + 1);
    } else if (strcmp(cmd, "list") == 0) {
        return cmd_list(argc - 1, argv + 1);
    } else if (strcmp(cmd, "info") == 0) {
        return cmd_info(argc - 1, argv + 1);
    } else if (strcmp(cmd, "destroy") == 0) {
        return cmd_destroy(argc - 1, argv + 1);
    } else {
        usage(argv[0]);
    }

    return 0;
}
