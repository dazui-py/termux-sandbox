#define _GNU_SOURCE
#include "rootfs.h"

#include "paths.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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
        if (!arch) arch = strdup("aarch64");
    }
    return arch ? arch : "aarch64";
}

char *rootfs_get_cached(void) {
    const char *cache_dir = sandbox_get_cache_dir();
    char *search_path = NULL;
    char *found = NULL;
    DIR *dir;
    struct dirent *entry;

    if (!cache_dir) return NULL;
    if (asprintf(&search_path, "%s/rootfs", cache_dir) < 0) return NULL;

    dir = opendir(search_path);
    if (!dir) {
        fprintf(stderr, "No rootfs cache directory: %s\n", search_path);
        free(search_path);
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (strstr(entry->d_name, ".tar.zst") || strstr(entry->d_name, ".tar.gz")) {
            if (asprintf(&found, "%s/%s", search_path, entry->d_name) < 0) found = NULL;
            break;
        }
    }

    closedir(dir);
    free(search_path);
    return found;
}

static int run_tar(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp("tar", argv);
        perror("exec tar");
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int rootfs_extract(const char *source, const char *dest) {
    if (!source || !dest) { errno = EINVAL; return -1; }
    if (strstr(source, ".tar.zst")) {
        char *const argv[] = { "tar", "--zstd", "-xf", (char *)source, "-C", (char *)dest, NULL };
        return run_tar(argv);
    }
    if (strstr(source, ".tar.gz")) {
        char *const argv[] = { "tar", "-xzf", (char *)source, "-C", (char *)dest, NULL };
        return run_tar(argv);
    }
    fprintf(stderr, "Unknown archive format: %s\n", source);
    errno = EINVAL;
    return -1;
}
