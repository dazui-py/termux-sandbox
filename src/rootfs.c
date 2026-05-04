#define _GNU_SOURCE
#include "rootfs.h"
#include "paths.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

const char *get_arch(void) {
    static const char *arch = NULL;
    if (!arch) {
        FILE *fp = popen("uname -m", "r");
        if (fp) {
            static char buf[32];
            if (fgets(buf, sizeof(buf), fp)) {
                buf[strcspn(buf, "\n")] = 0;
                arch = strdup(buf);
            }
            pclose(fp);
        }
        if (!arch) arch = "aarch64";
    }
    return arch;
}

char *rootfs_get_cached(void) {
    const char *cache_dir = sandbox_get_cache_dir();
    char search_path[512];
    snprintf(search_path, sizeof(search_path), "%s/rootfs", cache_dir);

    DIR *dir = opendir(search_path);
    if (!dir) return NULL;

    char *found = NULL;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            if (strstr(entry->d_name, ".tar.zst") || strstr(entry->d_name, ".tar.gz")) {
                asprintf(&found, "%s/%s", search_path, entry->d_name);
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

int rootfs_extract(const char *source, const char *dest) {
    char cmd[1024];

    if (strstr(source, ".tar.zst")) {
        snprintf(cmd, sizeof(cmd), "tar --zstd -xf \"%s\" -C \"%s\"", source, dest);
    } else if (strstr(source, ".tar.gz")) {
        snprintf(cmd, sizeof(cmd), "tar -xzf \"%s\" -C \"%s\"", source, dest);
    } else {
        fprintf(stderr, "Unknown archive format: %s\n", source);
        return -1;
    }

    return system(cmd);
}
