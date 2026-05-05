#define _GNU_SOURCE
#include "proot.h"
#include "paths.h"
#include "policy.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>

// Build and execute PRoot command for a sandbox
int sandbox_exec_proot(const char *name, char **cmd) {
    char *rootfs_path = sandbox_get_rootfs_path(name);
    char *policy_path = sandbox_get_policy_path(name);

    if (!rootfs_path || !policy_path) {
        fprintf(stderr, "Failed to build sandbox paths\n");
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    // Check if rootfs exists
    if (access(rootfs_path, F_OK) != 0) {
        fprintf(stderr, "Rootfs not found: %s\n", rootfs_path);
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    // Load policy
    policy_t policy;
    policy_load(policy_path, &policy);

    // Build PRoot command
    size_t cmdlen = 4096;
    char *proot_cmd = calloc(1, cmdlen);
    if (!proot_cmd) {
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    size_t offset = 0;

#define APPEND(...) do { \
        int n__ = snprintf(proot_cmd + offset, cmdlen - offset, __VA_ARGS__); \
        if (n__ < 0 || (size_t)n__ >= cmdlen - offset) { \
            fprintf(stderr, "PRoot command is too long\n"); \
            free(proot_cmd); \
            free(rootfs_path); \
            free(policy_path); \
            return 1; \
        } \
        offset += (size_t)n__; \
    } while (0)

    // Base PRoot command
    APPEND("proot --link2symlink -0 -r \"%s\"", rootfs_path);

    // Working directory
    APPEND(" -w /data/data/com.termux/files/home");

    // Bind the home directory inside rootfs to the expected path
    APPEND(" -b \"%s/data/data/com.termux/files/home:/data/data/com.termux/files/home\"",
        rootfs_path);

    // Bind the usr directory
    APPEND(" -b \"%s/data/data/com.termux/files/usr:/data/data/com.termux/files/usr\"",
        rootfs_path);

    // Add any grants from grants.conf
    char *grants_path = sandbox_get_grants_path(name);
    FILE *gf = grants_path ? fopen(grants_path, "r") : NULL;
    if (gf) {
        char line[512];
        while (fgets(line, sizeof(line), gf)) {
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) == 0) continue;

            // Parse grant: host_path:sandbox_path:mode
            char host_path[256], sandbox_path[256], mode[16];
            if (sscanf(line, "%255[^:]:%255[^:]:%15s", host_path, sandbox_path, mode) == 3) {
                APPEND(" -b \"%s:%s\"", host_path, sandbox_path);
            }
        }
        fclose(gf);
    }
    free(grants_path);

    // Environment variables and command to execute
    offset += snprintf(proot_cmd + offset, cmdlen - offset, " -- /usr/bin/env -i");

    offset += snprintf(proot_cmd + offset, cmdlen - offset,
        " HOME=/data/data/com.termux/files/home");
    offset += snprintf(proot_cmd + offset, cmdlen - offset,
        " PREFIX=/data/data/com.termux/files/usr");
    offset += snprintf(proot_cmd + offset, cmdlen - offset,
        " TMPDIR=/data/data/com.termux/files/usr/tmp");
    offset += snprintf(proot_cmd + offset, cmdlen - offset,
        " PATH=/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/bin/applets");
    offset += snprintf(proot_cmd + offset, cmdlen - offset,
        " SHELL=/data/data/com.termux/files/usr/bin/bash");

    if (cmd && cmd[0]) {
        // Execute specific command
        offset += snprintf(proot_cmd + offset, cmdlen - offset, " /data/data/com.termux/files/usr/bin/bash -c \"");
        for (int i = 0; cmd[i]; i++) {
            offset += snprintf(proot_cmd + offset, cmdlen - offset, "%s ", cmd[i]);
        }
        offset += snprintf(proot_cmd + offset, cmdlen - offset, "\"");
    } else {
        // Start interactive shell
        offset += snprintf(proot_cmd + offset, cmdlen - offset,
            " /data/data/com.termux/files/usr/bin/bash");
    }

    printf("Starting sandbox '%s'...\n", name);
    log_info("Executing PRoot: %s", proot_cmd);

    // Execute the command
    int ret = system(proot_cmd);

    free(proot_cmd);
    free(rootfs_path);
    free(policy_path);

    return WEXITSTATUS(ret);
}
