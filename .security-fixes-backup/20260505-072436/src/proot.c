#define _GNU_SOURCE
#include "proot.h"

#include "log.h"
#include "paths.h"
#include "policy.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define TERMUX_HOME "/data/data/com.termux/files/home"
#define TERMUX_PREFIX "/data/data/com.termux/files/usr"
#define TERMUX_TMPDIR "/data/data/com.termux/files/usr/tmp"
#define TERMUX_PATH "/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/bin/applets"
#define TERMUX_LOGIN "/data/data/com.termux/files/usr/bin/login"
#define TERMUX_BASH "/data/data/com.termux/files/usr/bin/bash"
#define HOST_PROOT "/data/data/com.termux/files/usr/bin/proot"

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} strvec_t;

static void strvec_free(strvec_t *v) {
    if (!v) return;
    for (size_t i = 0; i < v->len; i++) free(v->items[i]);
    free(v->items);
    v->items = NULL;
    v->len = 0;
    v->cap = 0;
}

static int strvec_reserve(strvec_t *v, size_t extra) {
    if (!v) { errno = EINVAL; return -1; }
    if (v->len + extra + 1 <= v->cap) return 0;
    size_t new_cap = v->cap ? v->cap * 2 : 32;
    while (new_cap < v->len + extra + 1) new_cap *= 2;
    char **new_items = realloc(v->items, new_cap * sizeof(char *));
    if (!new_items) return -1;
    v->items = new_items;
    v->cap = new_cap;
    return 0;
}

static int strvec_add(strvec_t *v, const char *s) {
    if (!s) { errno = EINVAL; return -1; }
    if (strvec_reserve(v, 1) != 0) return -1;
    v->items[v->len] = strdup(s);
    if (!v->items[v->len]) return -1;
    v->len++;
    v->items[v->len] = NULL;
    return 0;
}

static int strvec_addf(strvec_t *v, const char *fmt, ...) {
    char *out = NULL;
    va_list ap;
    if (!fmt) { errno = EINVAL; return -1; }
    va_start(ap, fmt);
    int n = vasprintf(&out, fmt, ap);
    va_end(ap);
    if (n < 0 || !out) return -1;
    int ret = strvec_add(v, out);
    free(out);
    return ret;
}

static const char *safe_getenv(const char *name, const char *fallback) {
    const char *v = getenv(name);
    if (!v || v[0] == '\0') return fallback;
    return v;
}

static int read_profile(const char *name, char **out_profile) {
    char *metadata_path = NULL;
    FILE *fp = NULL;
    char line[256];

    if (!out_profile) { errno = EINVAL; return -1; }
    *out_profile = strdup("dev");
    if (!*out_profile) return -1;

    metadata_path = sandbox_get_metadata_path(name);
    if (!metadata_path) return -1;

    fp = fopen(metadata_path, "r");
    free(metadata_path);
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "profile=", 8) == 0) {
            line[strcspn(line, "\r\n")] = '\0';
            char *value = line + 8;
            if (strcmp(value, "dev") == 0 || strcmp(value, "strict") == 0) {
                char *copy = strdup(value);
                if (!copy) { fclose(fp); return -1; }
                free(*out_profile);
                *out_profile = copy;
            }
            break;
        }
    }

    fclose(fp);
    return 0;
}

static int guest_file_exists(const char *rootfs_path, const char *guest_path) {
    char *host_path = NULL;
    int ok = 0;
    if (!rootfs_path || !guest_path || guest_path[0] != '/') return 0;
    if (asprintf(&host_path, "%s%s", rootfs_path, guest_path) < 0) return 0;
    ok = access(host_path, F_OK) == 0;
    free(host_path);
    return ok;
}

static int build_guest_env(strvec_t *envp, const char *name, const char *profile) {
    const char *term = safe_getenv("TERM", "xterm-256color");
    const char *colorterm = getenv("COLORTERM");
    const char *lang = getenv("LANG");

    if (strvec_addf(envp, "HOME=%s", TERMUX_HOME) != 0 ||
        strvec_addf(envp, "PREFIX=%s", TERMUX_PREFIX) != 0 ||
        strvec_addf(envp, "TMPDIR=%s", TERMUX_TMPDIR) != 0 ||
        strvec_addf(envp, "PATH=%s", TERMUX_PATH) != 0 ||
        strvec_addf(envp, "SHELL=%s", TERMUX_BASH) != 0 ||
        strvec_addf(envp, "TERM=%s", term) != 0 ||
        strvec_addf(envp, "SANDBOX_NAME=%s", name) != 0 ||
        strvec_addf(envp, "SANDBOX_PROFILE=%s", profile ? profile : "dev") != 0) {
        return -1;
    }

    if (colorterm && colorterm[0] != '\0' && strvec_addf(envp, "COLORTERM=%s", colorterm) != 0) return -1;
    if (lang && lang[0] != '\0') {
        if (strvec_addf(envp, "LANG=%s", lang) != 0) return -1;
    } else if (strvec_add(envp, "LANG=C.UTF-8") != 0) {
        return -1;
    }

    return 0;
}

static int add_bind(strvec_t *argv, const char *host, const char *guest) {
    if (!host || !guest || host[0] == '\0' || guest[0] != '/') { errno = EINVAL; return -1; }
    if (access(host, F_OK) != 0) {
        log_debug("Skipping missing bind: %s -> %s", host, guest);
        return 0;
    }
    return strvec_add(argv, "-b") == 0 && strvec_addf(argv, "%s:%s", host, guest) == 0 ? 0 : -1;
}

static int add_rootfs_self_binds(strvec_t *argv, const char *rootfs_path) {
    char *home_bind = NULL;
    char *usr_bind = NULL;
    int ret = -1;
    if (asprintf(&home_bind, "%s%s", rootfs_path, TERMUX_HOME) < 0 ||
        asprintf(&usr_bind, "%s%s", rootfs_path, TERMUX_PREFIX) < 0) goto out;
    if (add_bind(argv, home_bind, TERMUX_HOME) != 0 || add_bind(argv, usr_bind, TERMUX_PREFIX) != 0) goto out;
    ret = 0;
out:
    free(home_bind);
    free(usr_bind);
    return ret;
}

static int add_default_binds(strvec_t *argv, const char *profile) {
    if (add_bind(argv, "/system", "/system") != 0 ||
        add_bind(argv, "/apex", "/apex") != 0 ||
        add_bind(argv, "/linkerconfig", "/linkerconfig") != 0) return -1;

    if (profile && strcmp(profile, "strict") == 0) {
        return add_bind(argv, "/dev/null", "/dev/null") == 0 &&
               add_bind(argv, "/dev/zero", "/dev/zero") == 0 &&
               add_bind(argv, "/dev/random", "/dev/random") == 0 &&
               add_bind(argv, "/dev/urandom", "/dev/urandom") == 0 ? 0 : -1;
    }

    return add_bind(argv, "/dev", "/dev") == 0 &&
           add_bind(argv, "/proc", "/proc") == 0 &&
           add_bind(argv, "/sys", "/sys") == 0 ? 0 : -1;
}

static int contains_parent_ref(const char *path) {
    if (!path) return 1;
    if (strcmp(path, "..") == 0 || strncmp(path, "../", 3) == 0) return 1;
    if (strstr(path, "/../")) return 1;
    size_t n = strlen(path);
    return n >= 3 && strcmp(path + n - 3, "/..") == 0;
}

static int guest_grant_path_allowed(const char *guest_path) {
    static const char *allowed[] = { "/workspace", "/mnt/grants", "/home/grants", NULL };
    if (!guest_path || guest_path[0] != '/' || contains_parent_ref(guest_path)) return 0;
    for (int i = 0; allowed[i]; i++) {
        size_t n = strlen(allowed[i]);
        if (strcmp(guest_path, allowed[i]) == 0 || (strncmp(guest_path, allowed[i], n) == 0 && guest_path[n] == '/')) return 1;
    }
    return 0;
}

static int host_grant_path_allowed(const char *resolved_host) {
    const char *home = getenv("HOME");
    const char *prefix = getenv("PREFIX");
    const char *base = sandbox_get_base_dir();
    if (!resolved_host || resolved_host[0] != '/') return 0;
    if (prefix && prefix[0] != '\0') {
        size_t n = strlen(prefix);
        if (strcmp(resolved_host, prefix) == 0 || (strncmp(resolved_host, prefix, n) == 0 && resolved_host[n] == '/')) return 0;
    }
    if (home && home[0] != '\0' && strcmp(resolved_host, home) == 0) return 0;
    if (base && base[0] != '\0') {
        size_t n = strlen(base);
        if (strcmp(resolved_host, base) == 0 || (strncmp(resolved_host, base, n) == 0 && resolved_host[n] == '/')) return 0;
    }
    return 1;
}

static int add_grants(strvec_t *argv, const char *name) {
    char *grants_path = sandbox_get_grants_path(name);
    FILE *fp = NULL;
    char line[1024];
    if (!grants_path) return -1;
    fp = fopen(grants_path, "r");
    free(grants_path);
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        char host_path[512], guest_path[512], mode[32], resolved_host[PATH_MAX];
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        if (sscanf(line, "%511[^:]:%511[^:]:%31s", host_path, guest_path, mode) != 3) {
            log_error("Ignoring malformed grant: %s", line);
            continue;
        }
        if (strcmp(mode, "rw") != 0 && strcmp(mode, "ro") != 0) {
            log_error("Ignoring grant with invalid mode: %s", line);
            continue;
        }
        if (!guest_grant_path_allowed(guest_path)) {
            log_error("Ignoring grant with unsafe guest path: %s", guest_path);
            continue;
        }
        if (!realpath(host_path, resolved_host)) {
            log_error("Ignoring grant with unresolved host path: %s", host_path);
            continue;
        }
        if (!host_grant_path_allowed(resolved_host)) {
            log_error("Ignoring grant with forbidden host path: %s", resolved_host);
            continue;
        }
        if (strcmp(mode, "ro") == 0) {
            log_info("Grant mode 'ro' requested for %s, but PRoot bind read-only is not kernel-enforced", resolved_host);
        }
        if (add_bind(argv, resolved_host, guest_path) != 0) { fclose(fp); return -1; }
    }

    fclose(fp);
    return 0;
}

static void apply_child_limits(const char *profile) {
    struct rlimit rl;
    memset(&rl, 0, sizeof(rl));
    rl.rlim_cur = rl.rlim_max = (profile && strcmp(profile, "strict") == 0) ? 256 : 1024;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) log_debug("setrlimit(RLIMIT_NOFILE) failed: %s", strerror(errno));
    if (profile && strcmp(profile, "strict") == 0) {
        rl.rlim_cur = rl.rlim_max = 512UL * 1024UL * 1024UL;
        if (setrlimit(RLIMIT_FSIZE, &rl) != 0) log_debug("setrlimit(RLIMIT_FSIZE) failed: %s", strerror(errno));
    }
    if (setpriority(PRIO_PROCESS, 0, 10) != 0) log_debug("setpriority failed: %s", strerror(errno));
#ifdef PR_SET_DUMPABLE
    if (prctl(PR_SET_DUMPABLE, 0) != 0) log_debug("prctl(PR_SET_DUMPABLE) failed: %s", strerror(errno));
#endif
}

static void log_argv(const strvec_t *argv) {
    fprintf(stderr, "Executing PRoot argv:");
    for (size_t i = 0; argv && i < argv->len; i++) fprintf(stderr, " [%s]", argv->items[i]);
    fprintf(stderr, "\n");
}

static int build_proot_argv(strvec_t *argv, const char *name, const char *rootfs_path, const char *profile, char **cmd) {
    if (strvec_add(argv, "proot") != 0 ||
        strvec_add(argv, "--kill-on-exit") != 0 ||
        strvec_add(argv, "--link2symlink") != 0 ||
        strvec_add(argv, "-r") != 0 ||
        strvec_add(argv, rootfs_path) != 0 ||
        strvec_add(argv, "-w") != 0 ||
        strvec_add(argv, TERMUX_HOME) != 0) return -1;

    if (add_rootfs_self_binds(argv, rootfs_path) != 0 || add_default_binds(argv, profile) != 0 || add_grants(argv, name) != 0) return -1;

    if (cmd && cmd[0]) {
        for (int i = 0; cmd[i]; i++) if (strvec_add(argv, cmd[i]) != 0) return -1;
    } else {
        if (guest_file_exists(rootfs_path, TERMUX_LOGIN)) {
            if (strvec_add(argv, TERMUX_LOGIN) != 0) return -1;
        } else if (guest_file_exists(rootfs_path, TERMUX_BASH)) {
            if (strvec_add(argv, TERMUX_BASH) != 0) return -1;
        } else {
            fprintf(stderr, "No usable login or bash found inside sandbox rootfs\n");
            return -1;
        }
    }
    return 0;
}

int sandbox_exec_proot(const char *name, char **cmd) {
    char *rootfs_path = NULL, *policy_path = NULL, *profile = NULL;
    policy_t policy;
    strvec_t argv = {0}, envp = {0};
    int ret = 1;

    if (!sandbox_validate_name(name)) {
        fprintf(stderr, "Invalid sandbox name: %s\n", name ? name : "(null)");
        return 1;
    }

    rootfs_path = sandbox_get_rootfs_path(name);
    policy_path = sandbox_get_policy_path(name);
    if (!rootfs_path || !policy_path) { fprintf(stderr, "Failed to build sandbox paths\n"); goto out; }
    if (access(rootfs_path, F_OK) != 0) { fprintf(stderr, "Rootfs not found: %s\n", rootfs_path); goto out; }
    if (read_profile(name, &profile) != 0) { fprintf(stderr, "Failed to read sandbox profile\n"); goto out; }
    if (policy_load(policy_path, &policy) != 0) log_debug("Could not load policy file, using built-in defaults");
    if (build_guest_env(&envp, name, profile) != 0) { fprintf(stderr, "Failed to build guest environment\n"); goto out; }
    if (build_proot_argv(&argv, name, rootfs_path, profile, cmd) != 0) { fprintf(stderr, "Failed to build PRoot argv\n"); goto out; }

    printf("Starting sandbox '%s'...\n", name);
    log_argv(&argv);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); goto out; }
    if (pid == 0) {
        apply_child_limits(profile);
        execve(HOST_PROOT, argv.items, envp.items);
        perror("exec proot");
        _exit(127);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        perror("waitpid");
        goto out;
    }
    if (WIFEXITED(status)) ret = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) {
        fprintf(stderr, "Sandbox terminated by signal %d\n", WTERMSIG(status));
        ret = 128 + WTERMSIG(status);
    } else ret = 1;

out:
    strvec_free(&argv);
    strvec_free(&envp);
    free(rootfs_path);
    free(policy_path);
    free(profile);
    return ret;
}
