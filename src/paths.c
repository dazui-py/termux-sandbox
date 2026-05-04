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
        asprintf(&cached, "%s/.termux-sandbox", home);
        free(home);
    }
    return cached;
}

const char *sandbox_get_boxes_dir(void) {
    static const char *cached = NULL;
    if (!cached) {
        const char *base = sandbox_get_base_dir();
        asprintf((char **)&cached, "%s/boxes", base);
    }
    return cached;
}

const char *sandbox_get_cache_dir(void) {
    static const char *cached = NULL;
    if (!cached) {
        const char *base = sandbox_get_base_dir();
        asprintf((char **)&cached, "%s/cache", base);
    }
    return cached;
}

const char *sandbox_get_config_dir(void) {
    static const char *cached = NULL;
    if (!cached) {
        const char *base = sandbox_get_base_dir();
        asprintf((char **)&cached, "%s/config", base);
    }
    return cached;
}

char *sandbox_get_path(const char *name) {
    char *path;
    asprintf(&path, "%s/%s", sandbox_get_boxes_dir(), name);
    return path;
}

char *sandbox_get_rootfs_path(const char *name) {
    char *path;
    asprintf(&path, "%s/%s/rootfs", sandbox_get_boxes_dir(), name);
    return path;
}

char *sandbox_get_metadata_path(const char *name) {
    char *path;
    asprintf(&path, "%s/%s/metadata.conf", sandbox_get_boxes_dir(), name);
    return path;
}

char *sandbox_get_policy_path(const char *name) {
    char *path;
    asprintf(&path, "%s/%s/policy.conf", sandbox_get_boxes_dir(), name);
    return path;
}

char *sandbox_get_grants_path(const char *name) {
    char *path;
    asprintf(&path, "%s/%s/grants.conf", sandbox_get_boxes_dir(), name);
    return path;
}

char *sandbox_get_logs_path(const char *name) {
    char *path;
    asprintf(&path, "%s/%s/logs", sandbox_get_boxes_dir(), name);
    return path;
}

int sandbox_exists(const char *name) {
    char *path = sandbox_get_path(name);
    int ret = access(path, F_OK) == 0;
    free(path);
    return ret;
}

void mkdir_p(const char *path, mode_t mode) {
    char *p = strdup(path);
    char *sep = p;
    
    while (*sep) {
        sep = strchr(sep + 1, '/');
        if (sep) *sep = '\0';
        
        mkdir(p, mode);
        
        if (sep) *sep = '/';
    }
    free(p);
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

void sandbox_ensure_dirs(void) {
    const char *dirs[] = {
        sandbox_get_base_dir(),
        sandbox_get_boxes_dir(),
        sandbox_get_cache_dir(),
        sandbox_get_config_dir(),
        NULL
    };
    for (int i = 0; dirs[i]; i++) {
        mkdir_p(dirs[i], 0755);
    }
}
