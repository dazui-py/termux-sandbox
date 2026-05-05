#define _GNU_SOURCE
#include "proot.h"

#include "log.h"
#include "paths.h"
#include "policy.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int append_cmd(char **buf, size_t *cap, size_t *off, const char *fmt, ...) {
    va_list args;
    int needed;

    while (1) {
        va_start(args, fmt);
        needed = vsnprintf(*buf + *off, *cap - *off, fmt, args);
        va_end(args);

        if (needed < 0) {
            return -1;
        }

        if (*off + (size_t)needed < *cap) {
            *off += (size_t)needed;
            return 0;
        }

        size_t new_cap = *cap * 2;
        char *new_buf;

        while (*off + (size_t)needed >= new_cap) {
            new_cap *= 2;
        }

        new_buf = realloc(*buf, new_cap);
        if (!new_buf) {
            return -1;
        }

        *buf = new_buf;
        *cap = new_cap;
    }
}


static int shell_path_is_safe(const char *shell_path) {
    if (!shell_path || shell_path[0] != '/') {
        return 0;
    }

    /*
     * proot_cmd is currently executed through system(), so reject characters
     * that can break shell quoting or inject commands.
     */
    if (strpbrk(shell_path, " \t\r\n\"'`$\\;&|<>")) {
        return 0;
    }

    return 1;
}

static int guest_shell_exists(const char *rootfs_path, const char *guest_shell) {
    char *host_path = NULL;
    int ok = 0;

    if (!rootfs_path || !guest_shell || !shell_path_is_safe(guest_shell)) {
        return 0;
    }

    if (asprintf(&host_path, "%s%s", rootfs_path, guest_shell) < 0) {
        return 0;
    }

    ok = access(host_path, X_OK) == 0;
    free(host_path);
    return ok;
}

static char *fallback_shell(const char *rootfs_path) {
    const char *bash = "/data/data/com.termux/files/usr/bin/bash";
    const char *sh = "/data/data/com.termux/files/usr/bin/sh";

    if (guest_shell_exists(rootfs_path, bash)) {
        return strdup(bash);
    }

    if (guest_shell_exists(rootfs_path, sh)) {
        return strdup(sh);
    }

    return NULL;
}

static char *sandbox_detect_login_shell(const char *rootfs_path) {
    char *passwd_path = NULL;
    char *home_match_shell = NULL;
    char line[1024];
    uid_t uid = getuid();
    FILE *fp;

    if (!rootfs_path || rootfs_path[0] == '\0') {
        return NULL;
    }

    if (asprintf(&passwd_path,
                 "%s/data/data/com.termux/files/usr/etc/passwd",
                 rootfs_path) < 0) {
        return fallback_shell(rootfs_path);
    }

    fp = fopen(passwd_path, "r");
    free(passwd_path);

    if (!fp) {
        return fallback_shell(rootfs_path);
    }

    while (fgets(line, sizeof(line), fp)) {
        char *save = NULL;
        char *user;
        char *pass;
        char *uid_s;
        char *gid_s;
        char *gecos;
        char *home;
        char *shell;
        unsigned long parsed_uid;

        line[strcspn(line, "\n")] = '\0';

        user = strtok_r(line, ":", &save);
        pass = strtok_r(NULL, ":", &save);
        uid_s = strtok_r(NULL, ":", &save);
        gid_s = strtok_r(NULL, ":", &save);
        gecos = strtok_r(NULL, ":", &save);
        home = strtok_r(NULL, ":", &save);
        shell = strtok_r(NULL, ":", &save);

        (void)user;
        (void)pass;
        (void)gid_s;
        (void)gecos;

        if (!uid_s || !home || !shell) {
            continue;
        }

        if (!shell_path_is_safe(shell) || !guest_shell_exists(rootfs_path, shell)) {
            continue;
        }

        parsed_uid = strtoul(uid_s, NULL, 10);

        /*
         * Best match: same Android app UID.
         * This is what chsh should affect inside the sandbox.
         */
        if ((uid_t)parsed_uid == uid) {
            fclose(fp);
            free(home_match_shell);
            return strdup(shell);
        }

        /*
         * Fallback match: Termux home entry.
         * Useful if the rootfs passwd UID does not match this app install.
         */
        if (!home_match_shell &&
            strcmp(home, "/data/data/com.termux/files/home") == 0) {
            home_match_shell = strdup(shell);
        }
    }

    fclose(fp);

    if (home_match_shell) {
        return home_match_shell;
    }

    return fallback_shell(rootfs_path);
}


int sandbox_exec_proot(const char *name, char **cmd) {
    char *rootfs_path = NULL;
    char *policy_path = NULL;
    char *grants_path = NULL;
    char *proot_cmd = NULL;
    char *shell_path = NULL;
    size_t cmdlen = 2048;
    size_t offset = 0;
    int ret;

    if (!sandbox_validate_name(name)) {
        fprintf(stderr, "Invalid sandbox name: %s\n", name ? name : "(null)");
        return 1;
    }

    rootfs_path = sandbox_get_rootfs_path(name);
    policy_path = sandbox_get_policy_path(name);

    if (!rootfs_path || !policy_path) {
        fprintf(stderr, "Failed to build sandbox paths\n");
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    if (access(rootfs_path, F_OK) != 0) {
        fprintf(stderr, "Rootfs not found: %s\n", rootfs_path);
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    policy_t policy;
    policy_load(policy_path, &policy);

    shell_path = sandbox_detect_login_shell(rootfs_path);
    if (!shell_path) {
        fprintf(stderr, "No usable shell found inside sandbox rootfs\n");
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    proot_cmd = calloc(1, cmdlen);
    if (!proot_cmd) {
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    if (append_cmd(&proot_cmd, &cmdlen, &offset,
                   "/data/data/com.termux/files/usr/bin/env -i"
                   " HOME=/data/data/com.termux/files/home"
                   " PREFIX=/data/data/com.termux/files/usr"
                   " TMPDIR=/data/data/com.termux/files/usr/tmp"
                   " PATH=/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/bin/applets"
                   " SHELL=%s"
                   " TERM=xterm-256color"
                   " proot --link2symlink -r \"%s\"", shell_path, rootfs_path) != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -w /data/data/com.termux/files/home") != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b \"%s/data/data/com.termux/files/home:/data/data/com.termux/files/home\"",
                   rootfs_path) != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b \"%s/data/data/com.termux/files/usr:/data/data/com.termux/files/usr\"",
                   rootfs_path) != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b /system:/system") != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b /apex:/apex") != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b /linkerconfig:/linkerconfig") != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b /dev:/dev") != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b /proc:/proc") != 0 ||
        append_cmd(&proot_cmd, &cmdlen, &offset,
                   " -b /sys:/sys") != 0) {
        fprintf(stderr, "Failed to build proot command\n");
        free(proot_cmd);
        free(rootfs_path);
        free(policy_path);
        return 1;
    }

    grants_path = sandbox_get_grants_path(name);
    if (grants_path) {
        FILE *gf = fopen(grants_path, "r");
        if (gf) {
            char line[512];
            while (fgets(line, sizeof(line), gf)) {
                char host_path[256], sandbox_path[256], mode[16];

                line[strcspn(line, "\n")] = '\0';
                if (line[0] == '\0' || line[0] == '#') {
                    continue;
                }

                if (sscanf(line, "%255[^:]:%255[^:]:%15s", host_path, sandbox_path, mode) == 3) {
                }
            }
            fclose(gf);
        }
        free(grants_path);
    }


    if (cmd && cmd[0]) {
        if (append_cmd(&proot_cmd, &cmdlen, &offset,
                       " %s -c \"", shell_path) != 0) {
            free(proot_cmd);
            free(rootfs_path);
            free(policy_path);
            return 1;
        }

        for (int i = 0; cmd[i]; i++) {
            if (append_cmd(&proot_cmd, &cmdlen, &offset, "%s%s", i ? " " : "", cmd[i]) != 0) {
                free(proot_cmd);
                free(rootfs_path);
                free(policy_path);
                return 1;
            }
        }

        if (append_cmd(&proot_cmd, &cmdlen, &offset, "\"") != 0) {
            free(proot_cmd);
            free(rootfs_path);
            free(policy_path);
            return 1;
        }
    } else {
        if (append_cmd(&proot_cmd, &cmdlen, &offset,
                       " /data/data/com.termux/files/usr/bin/login") != 0) {
            free(proot_cmd);
            free(rootfs_path);
            free(policy_path);
            return 1;
        }
    }

    printf("Starting sandbox '%s'...\n", name);
    log_info("Executing PRoot: %s", proot_cmd);

    ret = system(proot_cmd);

    free(proot_cmd);
    free(rootfs_path);
    free(policy_path);
    free(shell_path);

    if (ret == -1) {
        return 1;
    }

    if (WIFEXITED(ret)) {
        return WEXITSTATUS(ret);
    }

    return 1;
}
