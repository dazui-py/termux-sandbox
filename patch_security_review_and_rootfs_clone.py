#!/usr/bin/env python3
from pathlib import Path
import re
import shutil
import sys
from datetime import datetime

ROOT = Path.cwd()
SRC = ROOT / "src"

if not (SRC / "rootfs.c").exists():
    print("ERROR: run this from the termux-sandbox project root")
    sys.exit(1)

backup_dir = ROOT / ".security-fixes-backup" / datetime.utcnow().strftime("%Y%m%d-%H%M%S")
backup_dir.mkdir(parents=True, exist_ok=True)


def backup(path: Path):
    if path.exists():
        dst = backup_dir / path.relative_to(ROOT)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dst)
        print(f"[+] backup {path} -> {dst}")


def write(path: Path, content: str):
    backup(path)
    path.write_text(content)
    print(f"[+] wrote {path}")

rootfs_h = r'''#ifndef ROOTFS_H
#define ROOTFS_H

/*
 * Rootfs helpers.
 *
 * rootfs_get_cached() may prompt the user to clone the termux-rootfs helper
 * repository if no local artifact exists. It never downloads/clones without
 * explicit user confirmation.
 */
char *rootfs_get_cached(void);

int rootfs_extract(const char *source, const char *dest);

const char *get_arch(void);

#endif
'''

rootfs_c = r'''#define _GNU_SOURCE
#include "rootfs.h"

#include "paths.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static int has_suffix(const char *s, const char *suffix) {
    size_t slen;
    size_t tlen;

    if (!s || !suffix) {
        return 0;
    }

    slen = strlen(s);
    tlen = strlen(suffix);

    return slen >= tlen && strcmp(s + slen - tlen, suffix) == 0;
}

static int is_rootfs_artifact_name(const char *name) {
    return name &&
           (has_suffix(name, ".tar.zst") ||
            has_suffix(name, ".tar.gz"));
}

static char *join_path2(const char *a, const char *b) {
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

static int run_argv(char *const argv[], const char *cwd) {
    pid_t pid;
    int status;

    if (!argv || !argv[0]) {
        errno = EINVAL;
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        if (cwd && chdir(cwd) != 0) {
            perror(cwd);
            _exit(127);
        }

        execvp(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }

    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return -1;
}

static int ask_yes_no(const char *question) {
    char answer[16];

    if (!question) {
        return 0;
    }

    fprintf(stderr, "%s [y/N] ", question);
    fflush(stderr);

    if (!fgets(answer, sizeof(answer), stdin)) {
        return 0;
    }

    return answer[0] == 'y' || answer[0] == 'Y';
}

static char *find_checksum_file(const char *dir_path) {
    DIR *dir;
    struct dirent *entry;
    char *found = NULL;

    if (!dir_path) {
        return NULL;
    }

    dir = opendir(dir_path);
    if (!dir) {
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "SHA256SUMS", 10) == 0) {
            found = join_path2(dir_path, entry->d_name);
            break;
        }
    }

    closedir(dir);
    return found;
}

static int checksum_mentions_artifact(const char *checksum_path, const char *artifact_name) {
    FILE *fp;
    char line[2048];
    int found = 0;

    if (!checksum_path || !artifact_name) {
        return 0;
    }

    fp = fopen(checksum_path, "r");
    if (!fp) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, artifact_name)) {
            found = 1;
            break;
        }
    }

    fclose(fp);
    return found;
}

static int verify_artifact_if_possible(const char *artifact_path) {
    char *dir = NULL;
    char *base = NULL;
    char *checksum = NULL;
    char *slash;
    int ret = 0;

    if (!artifact_path) {
        errno = EINVAL;
        return -1;
    }

    dir = strdup(artifact_path);
    if (!dir) {
        return -1;
    }

    slash = strrchr(dir, '/');
    if (!slash) {
        free(dir);
        return 0;
    }

    *slash = '\0';
    base = slash + 1;

    checksum = find_checksum_file(dir);
    if (!checksum) {
        fprintf(stderr,
                "warning: no SHA256SUMS file found next to rootfs artifact; using local artifact without integrity verification: %s\n",
                artifact_path);
        free(dir);
        return 0;
    }

    if (!checksum_mentions_artifact(checksum, base)) {
        fprintf(stderr,
                "warning: checksum file exists but does not mention %s; refusing artifact\n",
                base);
        free(checksum);
        free(dir);
        return -1;
    }

    char *argv[] = { "sha256sum", "-c", checksum, NULL };
    ret = run_argv(argv, dir);

    if (ret != 0) {
        fprintf(stderr, "rootfs checksum verification failed: %s\n", artifact_path);
        free(checksum);
        free(dir);
        return -1;
    }

    free(checksum);
    free(dir);
    return 0;
}

static char *find_newest_artifact_in_dir(const char *dir_path) {
    DIR *dir;
    struct dirent *entry;
    char *best = NULL;
    time_t best_mtime = 0;

    if (!dir_path) {
        return NULL;
    }

    dir = opendir(dir_path);
    if (!dir) {
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL) {
        char *candidate;
        struct stat st;

        if (entry->d_name[0] == '.') {
            continue;
        }

        if (!is_rootfs_artifact_name(entry->d_name)) {
            continue;
        }

        candidate = join_path2(dir_path, entry->d_name);
        if (!candidate) {
            continue;
        }

        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            if (!best || st.st_mtime >= best_mtime) {
                free(best);
                best = candidate;
                best_mtime = st.st_mtime;
                continue;
            }
        }

        free(candidate);
    }

    closedir(dir);
    return best;
}

static char *find_artifact_recursive_limited(const char *root, int depth) {
    DIR *dir;
    struct dirent *entry;
    char *found = NULL;

    if (!root || depth < 0) {
        return NULL;
    }

    found = find_newest_artifact_in_dir(root);
    if (found) {
        return found;
    }

    dir = opendir(root);
    if (!dir) {
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL && !found) {
        char *child;
        struct stat st;

        if (entry->d_name[0] == '.') {
            continue;
        }

        child = join_path2(root, entry->d_name);
        if (!child) {
            continue;
        }

        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode)) {
            found = find_artifact_recursive_limited(child, depth - 1);
        }

        free(child);
    }

    closedir(dir);
    return found;
}

static int clone_or_update_termux_rootfs_helper(const char *helper_dir) {
    struct stat st;
    int ret;

    if (!helper_dir) {
        errno = EINVAL;
        return -1;
    }

    if (stat(helper_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        char *argv[] = { "git", "-C", (char *)helper_dir, "pull", "--ff-only", NULL };
        fprintf(stderr, "Updating existing termux-rootfs helper: %s\n", helper_dir);
        ret = run_argv(argv, NULL);
        return ret == 0 ? 0 : -1;
    }

    char *argv[] = {
        "git", "clone", "--depth=1",
        "https://github.com/dazui-py/termux-rootfs",
        (char *)helper_dir,
        NULL
    };

    fprintf(stderr, "Cloning termux-rootfs helper into: %s\n", helper_dir);
    ret = run_argv(argv, NULL);
    return ret == 0 ? 0 : -1;
}

const char *get_arch(void) {
    static char arch[64];
    struct utsname uts;

    if (arch[0] == '\0') {
        if (uname(&uts) == 0 && uts.machine[0] != '\0') {
            snprintf(arch, sizeof(arch), "%s", uts.machine);
        } else {
            snprintf(arch, sizeof(arch), "aarch64");
        }
    }

    return arch;
}

char *rootfs_get_cached(void) {
    const char *cache_dir = sandbox_get_cache_dir();
    char *rootfs_cache = NULL;
    char *helper_dir = NULL;
    char *found = NULL;

    if (!cache_dir) {
        return NULL;
    }

    rootfs_cache = join_path2(cache_dir, "rootfs");
    helper_dir = join_path2(cache_dir, "termux-rootfs");

    if (!rootfs_cache || !helper_dir) {
        free(rootfs_cache);
        free(helper_dir);
        return NULL;
    }

    mkdir_p(rootfs_cache, 0755);

    found = find_newest_artifact_in_dir(rootfs_cache);
    if (found && verify_artifact_if_possible(found) == 0) {
        free(rootfs_cache);
        free(helper_dir);
        return found;
    }

    free(found);
    found = NULL;

    fprintf(stderr, "No usable rootfs artifact found in: %s\n", rootfs_cache);

    if (ask_yes_no("Clone/update termux-rootfs helper now?")) {
        if (clone_or_update_termux_rootfs_helper(helper_dir) != 0) {
            fprintf(stderr, "failed to clone/update termux-rootfs helper\n");
        } else {
            found = find_artifact_recursive_limited(helper_dir, 5);
            if (found && verify_artifact_if_possible(found) == 0) {
                fprintf(stderr, "Using rootfs artifact from helper repo: %s\n", found);
                free(rootfs_cache);
                free(helper_dir);
                return found;
            }
            free(found);
            found = NULL;
        }
    }

    fprintf(stderr,
            "No rootfs artifact is ready. Build one with termux-rootfs and copy it into:\n  %s\n",
            rootfs_cache);

    free(rootfs_cache);
    free(helper_dir);
    return NULL;
}

int rootfs_extract(const char *source, const char *dest) {
    int ret;

    if (!source || !dest) {
        errno = EINVAL;
        return -1;
    }

    if (has_suffix(source, ".tar.zst")) {
        char *argv[] = { "tar", "--zstd", "-xf", (char *)source, "-C", (char *)dest, NULL };
        ret = run_argv(argv, NULL);
    } else if (has_suffix(source, ".tar.gz")) {
        char *argv[] = { "tar", "-xzf", (char *)source, "-C", (char *)dest, NULL };
        ret = run_argv(argv, NULL);
    } else {
        fprintf(stderr, "Unknown rootfs archive format: %s\n", source);
        return -1;
    }

    return ret == 0 ? 0 : -1;
}
'''

policy_c = r'''#include "policy.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void policy_set_defaults(policy_t *policy) {
    if (!policy) {
        return;
    }

    policy->allow_sdcard = 0;
    policy->allow_host_home = 0;
    policy->allow_host_prefix = 0;
    policy->external_mounts = 0;
    policy->workspace_mount = 0;
    policy->logs = 1;
    policy->egress_default = EGRESS_DENY;
}

static char *trim(char *s) {
    char *end;

    if (!s) {
        return NULL;
    }

    while (isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return s;
}

static void strip_comment(char *s) {
    char *p;

    if (!s) {
        return;
    }

    p = strchr(s, '#');
    if (p) {
        *p = '\0';
    }
}

static int value_is_yes(const char *v) {
    return v &&
           (strcmp(v, "yes") == 0 ||
            strcmp(v, "true") == 0 ||
            strcmp(v, "1") == 0 ||
            strcmp(v, "on") == 0);
}

void policy_write_default(const char *path, const char *profile) {
    FILE *fp;

    if (!path) {
        return;
    }

    fp = fopen(path, "w");
    if (!fp) {
        perror(path);
        return;
    }

    if (profile && strcmp(profile, "strict") == 0) {
        fprintf(fp, "# Strict profile - maximum isolation\n");
        fprintf(fp, "allow_sdcard=no\n");
        fprintf(fp, "allow_host_home=no\n");
        fprintf(fp, "allow_host_prefix=no\n");
        fprintf(fp, "external_mounts=no\n");
        fprintf(fp, "workspace_mount=no\n");
        fprintf(fp, "egress_default=deny\n");
        fprintf(fp, "logs=yes\n");
    } else {
        fprintf(fp, "# Dev profile - project testing\n");
        fprintf(fp, "allow_sdcard=no\n");
        fprintf(fp, "allow_host_home=no\n");
        fprintf(fp, "allow_host_prefix=no\n");
        fprintf(fp, "external_mounts=no\n");
        fprintf(fp, "workspace_mount=optional\n");
        fprintf(fp, "egress_default=allow_granted\n");
        fprintf(fp, "logs=yes\n");
    }

    fclose(fp);
}

int policy_load(const char *path, policy_t *policy) {
    FILE *fp;
    char line[256];

    if (!policy) {
        return -1;
    }

    policy_set_defaults(policy);

    if (!path) {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *key;
        char *value;
        char *eq;

        strip_comment(line);
        key = trim(line);

        if (!key || key[0] == '\0') {
            continue;
        }

        eq = strchr(key, '=');
        if (!eq) {
            continue;
        }

        *eq = '\0';
        value = trim(eq + 1);
        key = trim(key);

        if (strcmp(key, "allow_sdcard") == 0) {
            policy->allow_sdcard = value_is_yes(value);
        } else if (strcmp(key, "allow_host_home") == 0) {
            policy->allow_host_home = value_is_yes(value);
        } else if (strcmp(key, "allow_host_prefix") == 0) {
            policy->allow_host_prefix = value_is_yes(value);
        } else if (strcmp(key, "external_mounts") == 0) {
            policy->external_mounts = value_is_yes(value);
        } else if (strcmp(key, "workspace_mount") == 0) {
            policy->workspace_mount = value_is_yes(value) || (value && strcmp(value, "optional") == 0);
        } else if (strcmp(key, "logs") == 0) {
            policy->logs = value_is_yes(value);
        } else if (strcmp(key, "egress_default") == 0) {
            if (value && strcmp(value, "allow_granted") == 0) {
                policy->egress_default = EGRESS_ALLOW_GRANTED;
            } else if (value && strcmp(value, "allow") == 0) {
                policy->egress_default = EGRESS_ALLOW;
            } else {
                policy->egress_default = EGRESS_DENY;
            }
        }
    }

    fclose(fp);
    return 0;
}
'''

write(SRC / "rootfs.h", rootfs_h)
write(SRC / "rootfs.c", rootfs_c)
write(SRC / "policy.c", policy_c)

# Best-effort proot grant hardening for the argv-based launcher created earlier.
proot = SRC / "proot.c"
if proot.exists():
    backup(proot)
    s = proot.read_text()
    original = s

    # Expand host grant blocklist if a host_grant_path_allowed() helper exists.
    m = re.search(r'static\s+int\s+host_grant_path_allowed\s*\([^)]*\)\s*\{', s)
    if m and "/proc" not in s[m.start():m.start()+1600]:
        insert_at = m.end()
        block = r'''
    static const char *forbidden_system_prefixes[] = {
        "/proc", "/sys", "/dev", "/system", "/apex", "/linkerconfig",
        "/sdcard", "/storage", "/mnt", "/vendor", "/product", "/odm",
        NULL
    };

    for (int i = 0; forbidden_system_prefixes[i]; i++) {
        const char *prefix = forbidden_system_prefixes[i];
        size_t n = strlen(prefix);
        if (strcmp(resolved_host, prefix) == 0 ||
            (strncmp(resolved_host, prefix, n) == 0 && resolved_host[n] == '/')) {
            return 0;
        }
    }
'''
        s = s[:insert_at] + block + s[insert_at:]
        print("[+] patched proot.c host grant system-path blocklist")

    # Reject ro grants if the parser has a mode check block. PRoot -b does not enforce ro.
    if "Grant mode 'ro' requested" in s:
        s = re.sub(
            r'if\s*\(strcmp\(mode,\s*"ro"\)\s*==\s*0\)\s*\{.*?\}',
            'if (strcmp(mode, "ro") == 0) {\n'
            '                    fprintf(stderr, "Grant mode ro is not supported: PRoot -b does not enforce read-only binds. Use rw explicitly or copy data into the sandbox.\\n");\n'
            '                    continue;\n'
            '                }',
            s,
            flags=re.S,
            count=1,
        )
        print("[+] patched proot.c to reject ro grants")

    # Gate argv logging behind TERMUX_SANDBOX_DEBUG if log_argv() is called unconditionally.
    s = re.sub(
        r'(?m)^(\s*)log_argv\(&([A-Za-z0-9_]+)\);',
        r'\1if (getenv("TERMUX_SANDBOX_DEBUG")) {\n\1    log_argv(&\2);\n\1}',
        s,
    )

    if s != original:
        proot.write_text(s)
        print("[+] wrote patched src/proot.c")
    else:
        print("[=] no proot.c pattern matched; skipped proot-specific patches")

# Best-effort sandbox.c hardening notes. Avoid blind destructive rewrite.
sandbox = SRC / "sandbox.c"
if sandbox.exists():
    text = sandbox.read_text()
    if "DT_UNKNOWN" in text:
        print("[!] sandbox.c still mentions DT_UNKNOWN. Add stat() fallback in cmd_list if not already done.")
    if "remove_tree" in text and "sandbox_get_boxes_dir" not in text[text.find("remove_tree") : text.find("remove_tree") + 2500]:
        print("[!] remove_tree exists; ensure cmd_destroy validates target is under sandbox_get_boxes_dir() before deleting.")

print("\nDone.")
print("Backups saved in:", backup_dir)
print("\nNext:")
print("  make clean")
print("  clang -g -O0 -Wall -Wextra -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer src/*.c -o termux-sandbox")
print("  grep -R 'system(' -n src || true")
