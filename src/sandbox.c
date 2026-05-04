#define _GNU_SOURCE
#include "sandbox.h"
#include "paths.h"
#include "policy.h"
#include "rootfs.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>

int cmd_create(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: termux-sandbox create <name> [--profile <profile>]\n");
        return 1;
    }

    const char *name = argv[1];
    const char *profile = "dev";  // default

    // Parse args
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) {
            profile = argv[i + 1];
            i++;
        }
    }

    // Validate name
    if (!sandbox_validate_name(name)) {
        fprintf(stderr, "Invalid sandbox name: %s\n", name);
        return 1;
    }

    // Check if exists
    if (sandbox_exists(name)) {
        fprintf(stderr, "Sandbox already exists: %s\n", name);
        return 1;
    }

    printf("Creating sandbox '%s' with profile '%s'...\n", name, profile);

    // Ensure directories
    sandbox_ensure_dirs();

    // Get rootfs artifact
    char *rootfs_source = rootfs_get_cached();
    if (!rootfs_source) {
        fprintf(stderr, "No rootfs artifact found. Please build or download one first.\n");
        return 1;
    }

    // Create sandbox directory
    char *sandbox_path = sandbox_get_path(name);
    char *rootfs_path = sandbox_get_rootfs_path(name);
    mkdir_p(sandbox_path, 0755);
    mkdir_p(rootfs_path, 0755);

    // Extract rootfs
    printf("Extracting rootfs...\n");
    if (rootfs_extract(rootfs_source, rootfs_path) != 0) {
        fprintf(stderr, "Failed to extract rootfs\n");
        free(sandbox_path);
        free(rootfs_path);
        return 1;
    }

    // Write metadata
    char *metadata_path = sandbox_get_metadata_path(name);
    FILE *fp = fopen(metadata_path, "w");
    if (fp) {
        fprintf(fp, "name=%s\n", name);
        fprintf(fp, "arch=%s\n", get_arch());
        fprintf(fp, "profile=%s\n", profile);
        fprintf(fp, "created_at=%ld\n", time(NULL));
        fprintf(fp, "rootfs_source=%s\n", rootfs_source);
        fclose(fp);
    }
    free(metadata_path);

    // Write policy
    char *policy_path = sandbox_get_policy_path(name);
    policy_write_default(policy_path, profile);
    free(policy_path);

    // Create empty grants
    char *grants_path = sandbox_get_grants_path(name);
    FILE *gf = fopen(grants_path, "w");
    if (gf) fclose(gf);
    free(grants_path);

    // Create logs directory
    char *logs_path = sandbox_get_logs_path(name);
    mkdir_p(logs_path, 0755);
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

    if (!sandbox_exists(name)) {
        fprintf(stderr, "Sandbox not found: %s\n", name);
        return 1;
    }

    // Build command to run
    char **cmd = malloc(sizeof(char *) * (argc - 1));
    for (int i = 2; i < argc; i++) {
        cmd[i - 2] = argv[i];
    }
    cmd[argc - 2] = NULL;

    return sandbox_exec_proot(name, cmd);
}

int cmd_list(int argc, char *argv[]) {
    (void)argc; (void)argv;
    const char *boxes_dir = sandbox_get_boxes_dir();
    DIR *dir = opendir(boxes_dir);
    if (!dir) {
        fprintf(stderr, "No sandboxes found\n");
        return 1;
    }

    printf("%-20s %-10s %-10s %s\n", "NAME", "ARCH", "PROFILE", "CREATED");
    printf("------------------------------------------------------------\n");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char *metadata_path = sandbox_get_metadata_path(entry->d_name);
        FILE *fp = fopen(metadata_path, "r");
        if (fp) {
            char line[256];
            char name[64] = "", arch[32] = "", profile[32] = "";
            time_t created = 0;

            while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "name=%63s", name) == 1) {}
                else if (sscanf(line, "arch=%31s", arch) == 1) {}
                else if (sscanf(line, "profile=%31s", profile) == 1) {}
                else if (sscanf(line, "created_at=%ld", &created) == 1) {}
            }
            fclose(fp);

            char time_str[32];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d", localtime(&created));
            printf("%-20s %-10s %-10s %s\n", name, arch, profile, time_str);
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

    if (!sandbox_exists(name)) {
        fprintf(stderr, "Sandbox not found: %s\n", name);
        return 1;
    }

    char *metadata_path = sandbox_get_metadata_path(name);
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
            time_t t;
            sscanf(line + 11, "%ld", &t);
            char buf[32];
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
            printf("Created: %s\n", buf);
        } else if (strncmp(line, "rootfs_source=", 13) == 0) {
            printf("Rootfs: %s", line + 13);
        }
    }
    fclose(fp);
    free(metadata_path);

    char *path = sandbox_get_path(name);
    printf("Path: %s\n", path);
    free(path);

    char *grants_path = sandbox_get_grants_path(name);
    FILE *gf = fopen(grants_path, "r");
    if (gf) {
        fseek(gf, 0, SEEK_END);
        long size = ftell(gf);
        fclose(gf);
        if (size > 0) {
            printf("Grants: configured\n");
        } else {
            printf("Grants: none\n");
        }
    } else {
        printf("Grants: none\n");
    }
    free(grants_path);

    return 0;
}

int cmd_destroy(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: termux-sandbox destroy <name>\n");
        return 1;
    }

    const char *name = argv[1];

    if (!sandbox_exists(name)) {
        fprintf(stderr, "Sandbox not found: %s\n", name);
        return 1;
    }

    char *path = sandbox_get_path(name);
    printf("Sandbox path: %s\n", path);
    printf("Type the sandbox name to confirm: ");

    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        free(path);
        return 1;
    }
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, name) != 0) {
        printf("Name mismatch. Aborted.\n");
        free(path);
        return 1;
    }

    printf("Destroying sandbox '%s'...\n", name);
    // Recursively delete the sandbox directory
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf \"%s\"", path);
    system(cmd);

    printf("Sandbox destroyed.\n");
    free(path);
    return 0;
}
