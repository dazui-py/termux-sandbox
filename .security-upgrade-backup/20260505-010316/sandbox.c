#define _GNU_SOURCE
#include "sandbox.h"

#include "log.h"
#include "paths.h"
#include "policy.h"
#include "rootfs.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int require_valid_name(const char *name) {
    if (!sandbox_validate_name(name)) {
        fprintf(stderr, "Invalid sandbox name: %s\n", name ? name : "(null)");
        return 0;
    }
    return 1;
}


static int ensure_termux_runtime_dirs(const char *rootfs_path) {
    char *apt_cache = NULL;
    char *apt_partial = NULL;
    char *apt_lists_partial = NULL;
    char *tmpdir = NULL;
    int ret = -1;

    if (!rootfs_path || rootfs_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (asprintf(&apt_cache,
                 "%s/data/data/com.termux/cache/apt/archives",
                 rootfs_path) < 0 ||
        asprintf(&apt_partial,
                 "%s/data/data/com.termux/cache/apt/archives/partial",
                 rootfs_path) < 0 ||
        asprintf(&apt_lists_partial,
                 "%s/data/data/com.termux/files/usr/var/lib/apt/lists/partial",
                 rootfs_path) < 0 ||
        asprintf(&tmpdir,
                 "%s/data/data/com.termux/files/usr/tmp",
                 rootfs_path) < 0) {
        goto out;
    }

    if (mkdir_p(apt_cache, 0700) != 0 ||
        mkdir_p(apt_partial, 0700) != 0 ||
        mkdir_p(apt_lists_partial, 0700) != 0 ||
        mkdir_p(tmpdir, 0700) != 0) {
        goto out;
    }

    ret = 0;

out:
    free(apt_cache);
    free(apt_partial);
    free(apt_lists_partial);
    free(tmpdir);
    return ret;
}


static int remove_playstore_motd(const char *rootfs_path) {
    char *motd_path = NULL;

    if (!rootfs_path || rootfs_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (asprintf(&motd_path,
                 "%s/data/data/com.termux/files/usr/etc/motd-playstore",
                 rootfs_path) < 0) {
        return -1;
    }

    /*
     * Remove outdated Google Play Termux warning from sandbox rootfs.
     * Missing file is not an error.
     */
    if (unlink(motd_path) != 0 && errno != ENOENT) {
        free(motd_path);
        return -1;
    }

    free(motd_path);
    return 0;
}


int cmd_create(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: termux-sandbox create <name> [--profile <profile>]\n");
        return 1;
    }

    const char *name = argv[1];
    const char *profile = "dev";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) {
            profile = argv[i + 1];
            i++;
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            return 1;
        }
    }

    if (!require_valid_name(name)) {
        return 1;
    }

    if (strcmp(profile, "dev") != 0 && strcmp(profile, "strict") != 0) {
        fprintf(stderr, "Invalid profile: %s\n", profile);
        fprintf(stderr, "Valid profiles: dev, strict\n");
        return 1;
    }

    if (sandbox_exists(name)) {
        fprintf(stderr, "Sandbox already exists: %s\n", name);
        return 1;
    }

    printf("Creating sandbox '%s' with profile '%s'...\n", name, profile);

    if (sandbox_ensure_dirs() != 0) {
        fprintf(stderr, "Failed to create sandbox directories\n");
        return 1;
    }

    char *rootfs_source = rootfs_get_cached();
    if (!rootfs_source) {
        const char *cache = sandbox_get_cache_dir();
        fprintf(stderr, "No rootfs artifact found.\n");
        if (cache) {
            fprintf(stderr, "Copy a .tar.zst or .tar.gz rootfs artifact into: %s/rootfs\n", cache);
        }
        return 1;
    }

    char *sandbox_path = sandbox_get_path(name);
    char *rootfs_path = sandbox_get_rootfs_path(name);

    if (!sandbox_path || !rootfs_path) {
        fprintf(stderr, "Failed to build sandbox paths\n");
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    if (mkdir_p(sandbox_path, 0755) != 0) {
        perror(sandbox_path);
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    if (mkdir_p(rootfs_path, 0755) != 0) {
        perror(rootfs_path);
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    printf("Extracting rootfs...\n");
    if (rootfs_extract(rootfs_source, rootfs_path) != 0) {
        fprintf(stderr, "Failed to extract rootfs\n");
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    if (ensure_termux_runtime_dirs(rootfs_path) != 0) {
        perror("ensure_termux_runtime_dirs");
        free(sandbox_path);
        free(rootfs_path);
        free(rootfs_source);
        return 1;
    }

    if (remove_playstore_motd(rootfs_path) != 0) {
        perror("remove_playstore_motd");
        free(sandbox_path);
        free(rootfs_path);
        free(rootfs_source);
        return 1;
    }



    char *metadata_path = sandbox_get_metadata_path(name);
    if (!metadata_path) {
        fprintf(stderr, "Failed to build metadata path\n");
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    FILE *fp = fopen(metadata_path, "w");
    if (!fp) {
        perror(metadata_path);
        free(metadata_path);
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    fprintf(fp, "name=%s\n", name);
    fprintf(fp, "arch=%s\n", get_arch());
    fprintf(fp, "profile=%s\n", profile);
    fprintf(fp, "created_at=%ld\n", (long)time(NULL));
    fprintf(fp, "rootfs_source=%s\n", rootfs_source);
    fclose(fp);
    free(metadata_path);

    char *policy_path = sandbox_get_policy_path(name);
    if (!policy_path) {
        fprintf(stderr, "Failed to build policy path\n");
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }
    policy_write_default(policy_path, profile);
    free(policy_path);

    char *grants_path = sandbox_get_grants_path(name);
    if (!grants_path) {
        fprintf(stderr, "Failed to build grants path\n");
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    FILE *gf = fopen(grants_path, "w");
    if (!gf) {
        perror(grants_path);
        free(grants_path);
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }
    fclose(gf);
    free(grants_path);

    char *logs_path = sandbox_get_logs_path(name);
    if (!logs_path) {
        fprintf(stderr, "Failed to build logs path\n");
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    if (mkdir_p(logs_path, 0755) != 0) {
        perror(logs_path);
        free(logs_path);
        free(rootfs_source);
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }
    free(logs_path);

    printf("Sandbox '%s' created successfully.\n", name);

    free(sandbox_path);
    free(rootfs_path);
    free(rootfs_source);
    return 0;
}

int cmd_enter(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: termux-sandbox enter <name>\n");
        return 1;
    }

    const char *name = argv[1];

    if (!require_valid_name(name)) {
        return 1;
    }

    if (!sandbox_exists(name)) {
        fprintf(stderr, "Sandbox not found: %s\n", name);
        return 1;
    }

    return sandbox_exec_proot(name, NULL);
}

int cmd_run(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: termux-sandbox run <name> <command> [args...]\n");
        return 1;
    }

    const char *name = argv[1];

    if (!require_valid_name(name)) {
        return 1;
    }

    if (!sandbox_exists(name)) {
        fprintf(stderr, "Sandbox not found: %s\n", name);
        return 1;
    }

    char **cmd = calloc((size_t)(argc - 1), sizeof(char *));
    if (!cmd) {
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        cmd[i - 2] = argv[i];
    }
    cmd[argc - 2] = NULL;

    int ret = sandbox_exec_proot(name, cmd);
    free(cmd);
    return ret;
}

int cmd_list(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    const char *boxes_dir = sandbox_get_boxes_dir();
    if (!boxes_dir) {
        fprintf(stderr, "Failed to resolve boxes directory\n");
        return 1;
    }

    DIR *dir = opendir(boxes_dir);
    if (!dir) {
        fprintf(stderr, "No sandboxes found\n");
        return 1;
    }

    printf("%-20s %-10s %-10s %s\n", "NAME", "ARCH", "PROFILE", "CREATED");
    printf("------------------------------------------------------------\n");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) {
            continue;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char *metadata_path = sandbox_get_metadata_path(entry->d_name);
        if (!metadata_path) {
            continue;
        }

        FILE *fp = fopen(metadata_path, "r");
        if (fp) {
            char line[256];
            char found_name[64] = "";
            char arch[32] = "";
            char profile[32] = "";
            time_t created = 0;

            while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "name=%63s", found_name) == 1) {
                } else if (sscanf(line, "arch=%31s", arch) == 1) {
                } else if (sscanf(line, "profile=%31s", profile) == 1) {
                } else if (sscanf(line, "created_at=%ld", &created) == 1) {
                }
            }
            fclose(fp);

            char time_str[32] = "unknown";
            if (created > 0) {
                struct tm *tm = localtime(&created);
                if (tm) {
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d", tm);
                }
            }

            printf("%-20s %-10s %-10s %s\n",
                   found_name[0] ? found_name : entry->d_name,
                   arch[0] ? arch : "unknown",
                   profile[0] ? profile : "unknown",
                   time_str);
        }
        free(metadata_path);
    }

    closedir(dir);
    return 0;
}

int cmd_info(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: termux-sandbox info <name>\n");
        return 1;
    }

    const char *name = argv[1];

    if (!require_valid_name(name)) {
        return 1;
    }

    if (!sandbox_exists(name)) {
        fprintf(stderr, "Sandbox not found: %s\n", name);
        return 1;
    }

    char *metadata_path = sandbox_get_metadata_path(name);
    if (!metadata_path) {
        fprintf(stderr, "Failed to build metadata path\n");
        return 1;
    }

    FILE *fp = fopen(metadata_path, "r");
    if (!fp) {
        fprintf(stderr, "Failed to read metadata\n");
        free(metadata_path);
        return 1;
    }

    printf("Name: %s\n", name);

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "arch=", 5) == 0) {
            printf("Arch: %s", line + 5);
        } else if (strncmp(line, "profile=", 8) == 0) {
            printf("Profile: %s", line + 8);
        } else if (strncmp(line, "created_at=", 11) == 0) {
            time_t t = 0;
            sscanf(line + 11, "%ld", &t);
            char buf[32] = "unknown";
            if (t > 0) {
                struct tm *tm = localtime(&t);
                if (tm) {
                    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
                }
            }
            printf("Created: %s\n", buf);
        } else if (strncmp(line, "rootfs_source=", 14) == 0) {
            printf("Rootfs: %s", line + 14);
        }
    }
    fclose(fp);
    free(metadata_path);

    char *path = sandbox_get_path(name);
    if (path) {
        printf("Path: %s\n", path);
        free(path);
    }

    char *grants_path = sandbox_get_grants_path(name);
    if (grants_path) {
        FILE *gf = fopen(grants_path, "r");
        if (gf) {
            fseek(gf, 0, SEEK_END);
            long size = ftell(gf);
            fclose(gf);
            printf("Grants: %s\n", size > 0 ? "configured" : "none");
        } else {
            printf("Grants: none\n");
        }
        free(grants_path);
    } else {
        printf("Grants: none\n");
    }

    return 0;
}

int cmd_destroy(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: termux-sandbox destroy <name>\n");
        return 1;
    }

    const char *name = argv[1];

    if (!require_valid_name(name)) {
        return 1;
    }

    if (!sandbox_exists(name)) {
        fprintf(stderr, "Sandbox not found: %s\n", name);
        return 1;
    }

    char *path = sandbox_get_path(name);
    if (!path) {
        fprintf(stderr, "Failed to build sandbox path\n");
        return 1;
    }

    printf("Sandbox path: %s\n", path);
    printf("Type the sandbox name to confirm: ");

    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        free(path);
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';

    if (strcmp(input, name) != 0) {
        printf("Name mismatch. Aborted.\n");
        free(path);
        return 1;
    }

    printf("Destroying sandbox '%s'...\n", name);

    char rm_cmd[1024];
    int n = snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf -- \"%s\"", path);
    if (n < 0 || (size_t)n >= sizeof(rm_cmd)) {
        fprintf(stderr, "Sandbox path too long\n");
        free(path);
        return 1;
    }

    int ret = system(rm_cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to destroy sandbox\n");
        free(path);
        return 1;
    }

    printf("Sandbox destroyed.\n");
    free(path);
    return 0;
}
