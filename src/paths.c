#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include "paths.h"

static char *get_home_dir(void) {
    const char *home = getenv("HOME");
    if (!home) home = "/data/data/com.termux/files/home";
    return strdup(home);
}

const char *sandbox_get_base_dir(void) {
    static char *cached = NULL;
    if (!cached) {
        char *home = get_home_dir();
        if (!home) return NULL;
        if (asprintf(&cached, "%s/.termux-sandbox", home) < 0) {
            cached = NULL;
        }
        free(home);
    }
    return cached;
}

const char *sandbox_get_boxes_dir(void) {
    static char *cached = NULL;
    if (!cached) {
        const char *base = sandbox_get_base_dir();
        if (!base) return NULL;
        if (asprintf(&cached, "%s/boxes", base) < 0) {
            cached = NULL;
        }
    }
    return cached;
}

const char *sandbox_get_cache_dir(void) {
    static char *cached = NULL;
    if (!cached) {
        const char *base = sandbox_get_base_dir();
        if (!base) return NULL;
        if (asprintf(&cached, "%s/cache", base) < 0) {
            cached = NULL;
        }
    }
    return cached;
}

const char *sandbox_get_config_dir(void) {
    static char *cached = NULL;
    if (!cached) {
        const char *base = sandbox_get_base_dir();
        if (!base) return NULL;
        if (asprintf(&cached, "%s/config", base) < 0) {
            cached = NULL;
        }
    }
    return cached;
}

char *sandbox_get_path(const char *name) {
    char *path = NULL;
    const char *boxes = sandbox_get_boxes_dir();
    if (!boxes) return NULL;
    asprintf(&path, "%s/%s", boxes, name);
    return path;
}

char *sandbox_get_rootfs_path(const char *name) {
    char *path = NULL;
    const char *boxes = sandbox_get_boxes_dir();
    if (!boxes) return NULL;
    asprintf(&path, "%s/%s/rootfs", boxes, name);
    return path;
}

char *sandbox_get_metadata_path(const char *name) {
    char *path = NULL;
    const char *boxes = sandbox_get_boxes_dir();
    if (!boxes) return NULL;
    asprintf(&path, "%s/%s/metadata.conf", boxes, name);
    return path;
}

char *sandbox_get_policy_path(const char *name) {
    char *path = NULL;
    const char *boxes = sandbox_get_boxes_dir();
    if (!boxes) return NULL;
    asprintf(&path, "%s/%s/policy.conf", boxes, name);
    return path;
}

char *sandbox_get_grants_path(const char *name) {
    char *path = NULL;
    const char *boxes = sandbox_get_boxes_dir();
    if (!boxes) return NULL;
    asprintf(&path, "%s/%s/grants.conf", boxes, name);
    return path;
}

char *sandbox_get_logs_path(const char *name) {
    char *path = NULL;
    const char *boxes = sandbox_get_boxes_dir();
    if (!boxes) return NULL;
    asprintf(&path, "%s/%s/logs", boxes, name);
    return path;
}

int sandbox_exists(const char *name) {
    char *path = sandbox_get_path(name);
    int ret = access(path, F_OK) == 0;
    free(path);
    return ret;
}

int mkdir_p(const char *path, mode_t mode) {
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    char *p = strdup(path);
    if (!p) return -1;

    char *sep = p;
    int ret = 0;

    while (*sep) {
        sep = strchr(sep + 1, '/');
        if (sep) *sep = '\0';

        if (mkdir(p, mode) != 0 && errno != EEXIST) {
            ret = -1;
            break;
        }

        if (sep) *sep = '/';
    }

    if (ret == 0 && mkdir(p, mode) != 0 && errno != EEXIST) {
        ret = -1;
    }

    free(p);
    return ret;
}

int sandbox_validate_name(const char *name) {
    if (!name || strlen(name) == 0) return 0;
    if (strlen(name) > 64) return 0;
    
    for (size_t i = 0; name[i]; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            return 0;
        }
    }
    return 1;
}

int sandbox_ensure_dirs(void) {
    const char *dirs[] = {
        sandbox_get_base_dir(),
        sandbox_get_boxes_dir(),
        sandbox_get_cache_dir(),
        sandbox_get_config_dir(),
        NULL
    };
    for (int i = 0; dirs[i]; i++) {
        if (dirs[i] == NULL) {
            fprintf(stderr, "NULL path at index %d\n", i);
            return -1;
        }
        if (mkdir_p(dirs[i], 0755) != 0) {
            perror("mkdir_p");
            return -1;
        }
    }
    return 0;
}
