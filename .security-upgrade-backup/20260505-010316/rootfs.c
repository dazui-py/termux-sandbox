#define _GNU_SOURCE
#include "rootfs.h"

#include "paths.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *get_arch(void) {
    static char *arch = NULL;

    if (!arch) {
        FILE *fp = popen("uname -m", "r");
        if (fp) {
            char buf[32];
            if (fgets(buf, sizeof(buf), fp)) {
                buf[strcspn(buf, "\n")] = '\0';
                arch = strdup(buf);
            }
            pclose(fp);
        }

        if (!arch) {
            arch = strdup("aarch64");
        }
    }

    return arch ? arch : "aarch64";
}

char *rootfs_get_cached(void) {
    const char *cache_dir = sandbox_get_cache_dir();
    char *search_path = NULL;
    char *found = NULL;
    DIR *dir;
    struct dirent *entry;

    if (!cache_dir) {
        return NULL;
    }

    if (asprintf(&search_path, "%s/rootfs", cache_dir) < 0) {
        return NULL;
    }

    dir = opendir(search_path);
    if (!dir) {
        fprintf(stderr, "No rootfs cache directory: %s\n", search_path);
        free(search_path);
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        if (strstr(entry->d_name, ".tar.zst") || strstr(entry->d_name, ".tar.gz")) {
            if (asprintf(&found, "%s/%s", search_path, entry->d_name) < 0) {
                found = NULL;
            }
            break;
        }
    }

    closedir(dir);
    free(search_path);
    return found;
}

int rootfs_extract(const char *source, const char *dest) {
    char cmd[1024];
    int n;

    if (!source || !dest) {
        errno = EINVAL;
        return -1;
    }

    if (strstr(source, ".tar.zst")) {
        n = snprintf(cmd, sizeof(cmd), "tar --zstd -xf \"%s\" -C \"%s\"", source, dest);
    } else if (strstr(source, ".tar.gz")) {
        n = snprintf(cmd, sizeof(cmd), "tar -xzf \"%s\" -C \"%s\"", source, dest);
    } else {
        fprintf(stderr, "Unknown archive format: %s\n", source);
        return -1;
    }

    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "Rootfs extract command is too long\n");
        return -1;
    }

    return system(cmd);
}
