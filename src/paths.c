#define _GNU_SOURCE
#include "paths.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char *get_home_dir(void) {
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') {
        home = "/data/data/com.termux/files/home";
    }
    return strdup(home);
}

static char *join2(const char *a, const char *b) {
    char *out = NULL;

    if (!a || !b || a[0] == '\0' || b[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }

    if (asprintf(&out, "%s/%s", a, b) < 0) {
        errno = ENOMEM;
        return NULL;
    }

    return out;
}

const char *sandbox_get_base_dir(void) {
    static char *cached = NULL;

    if (!cached) {
        char *home = get_home_dir();
        if (!home) {
            return NULL;
        }

        cached = join2(home, ".termux-sandbox");
        free(home);
    }

    return cached;
}

const char *sandbox_get_boxes_dir(void) {
    static char *cached = NULL;

    if (!cached) {
        const char *base = sandbox_get_base_dir();
        cached = join2(base, "boxes");
    }

    return cached;
}

const char *sandbox_get_cache_dir(void) {
    static char *cached = NULL;

    if (!cached) {
        const char *base = sandbox_get_base_dir();
        cached = join2(base, "cache");
    }

    return cached;
}

const char *sandbox_get_config_dir(void) {
    static char *cached = NULL;

    if (!cached) {
        const char *base = sandbox_get_base_dir();
        cached = join2(base, "config");
    }

    return cached;
}

char *sandbox_get_path(const char *name) {
    const char *boxes = sandbox_get_boxes_dir();
    if (!boxes || !name) {
        errno = EINVAL;
        return NULL;
    }

    return join2(boxes, name);
}

char *sandbox_get_rootfs_path(const char *name) {
    char *box = sandbox_get_path(name);
    char *path = NULL;

    if (!box) {
        return NULL;
    }

    path = join2(box, "rootfs");
    free(box);
    return path;
}

char *sandbox_get_metadata_path(const char *name) {
    char *box = sandbox_get_path(name);
    char *path = NULL;

    if (!box) {
        return NULL;
    }

    path = join2(box, "metadata.conf");
    free(box);
    return path;
}

char *sandbox_get_policy_path(const char *name) {
    char *box = sandbox_get_path(name);
    char *path = NULL;

    if (!box) {
        return NULL;
    }

    path = join2(box, "policy.conf");
    free(box);
    return path;
}

char *sandbox_get_grants_path(const char *name) {
    char *box = sandbox_get_path(name);
    char *path = NULL;

    if (!box) {
        return NULL;
    }

    path = join2(box, "grants.conf");
    free(box);
    return path;
}

char *sandbox_get_logs_path(const char *name) {
    char *box = sandbox_get_path(name);
    char *path = NULL;

    if (!box) {
        return NULL;
    }

    path = join2(box, "logs");
    free(box);
    return path;
}

int sandbox_exists(const char *name) {
    char *path = sandbox_get_path(name);
    int ret = 0;

    if (!path) {
        return 0;
    }

    ret = access(path, F_OK) == 0;
    free(path);
    return ret;
}

int mkdir_p(const char *path, mode_t mode) {
    char *tmp = NULL;
    size_t len;

    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    tmp = strdup(path);
    if (!tmp) {
        return -1;
    }

    len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
        len--;
    }

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') {
            continue;
        }

        *p = '\0';
        if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
            int saved = errno;
            free(tmp);
            errno = saved;
            return -1;
        }
        *p = '/';
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        int saved = errno;
        free(tmp);
        errno = saved;
        return -1;
    }

    free(tmp);
    return 0;
}

int sandbox_validate_name(const char *name) {
    if (!name || name[0] == '\0') {
        return 0;
    }

    if (strlen(name) > 64) {
        return 0;
    }

    for (size_t i = 0; name[i]; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '_')) {
            return 0;
        }
    }

    return 1;
}

int sandbox_ensure_dirs(void) {
    char *rootfs_cache = NULL;
    const char *cache = sandbox_get_cache_dir();

    if (cache) {
        rootfs_cache = join2(cache, "rootfs");
    }

    const char *dirs[] = {
        sandbox_get_base_dir(),
        sandbox_get_boxes_dir(),
        cache,
        rootfs_cache,
        sandbox_get_config_dir(),
        NULL
    };

    for (int i = 0; dirs[i]; i++) {
        if (mkdir_p(dirs[i], 0755) != 0) {
            perror(dirs[i]);
            free(rootfs_cache);
            return -1;
        }
    }

    free(rootfs_cache);
    return 0;
}
