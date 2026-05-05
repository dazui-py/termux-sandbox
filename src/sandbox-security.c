#define _GNU_SOURCE
#include "sandbox-security.h"

#include "paths.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TERMUX_HOME "/data/data/com.termux/files/home"
#define TERMUX_PREFIX "/data/data/com.termux/files/usr"

static int has_prefix_path(const char *path, const char *prefix) {
    size_t n;

    if (!path || !prefix) {
        return 0;
    }

    n = strlen(prefix);

    return strcmp(path, prefix) == 0 ||
           (strncmp(path, prefix, n) == 0 && path[n] == '/');
}

static int write_file_if_changed(const char *path, const char *content, mode_t mode) {
    FILE *fp;
    char *old = NULL;
    long size;

    if (!path || !content) {
        errno = EINVAL;
        return -1;
    }

    fp = fopen(path, "r");
    if (fp) {
        if (fseek(fp, 0, SEEK_END) == 0) {
            size = ftell(fp);

            if (size >= 0 && fseek(fp, 0, SEEK_SET) == 0) {
                old = calloc(1, (size_t)size + 1);

                if (old &&
                    fread(old, 1, (size_t)size, fp) == (size_t)size &&
                    strcmp(old, content) == 0) {
                    free(old);
                    fclose(fp);
                    chmod(path, mode);
                    return 0;
                }
            }
        }

        free(old);
        fclose(fp);
    }

    fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }

    if (fputs(content, fp) == EOF) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    chmod(path, mode);
    return 0;
}

static int append_line_if_missing(const char *path, const char *needle, const char *line) {
    FILE *fp;
    char buf[1024];

    if (!path || !needle || !line) {
        errno = EINVAL;
        return -1;
    }

    fp = fopen(path, "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, needle)) {
                fclose(fp);
                return 0;
            }
        }

        fclose(fp);
    }

    fp = fopen(path, "a");
    if (!fp) {
        return -1;
    }

    if (fprintf(fp, "\n%s\n", line) < 0) {
        fclose(fp);
        return -1;
    }

    return fclose(fp) == 0 ? 0 : -1;
}

int sandbox_security_path_is_allowed(const char *path) {
    return path &&
           (has_prefix_path(path, TERMUX_HOME) ||
            has_prefix_path(path, TERMUX_PREFIX));
}

int sandbox_security_path_is_protected(const char *path) {
    static const char *protected_prefixes[] = {
        "/data",
        "/data/data",
        "/system",
        "/apex",
        "/linkerconfig",
        "/proc",
        "/sys",
        "/dev",
        "/sdcard",
        "/storage",
        "/mnt",
        NULL
    };

    if (!path) {
        return 0;
    }

    for (int i = 0; protected_prefixes[i]; i++) {
        if (has_prefix_path(path, protected_prefixes[i])) {
            return 1;
        }
    }

    return 0;
}

int sandbox_security_install(const char *rootfs_path) {
    char *home_dir = NULL;
    char *guard_path = NULL;
    char *bashrc_path = NULL;
    char *zshrc_path = NULL;
    int ret = -1;

    static const char guard_script[] =
        "# sandbox-security\n"
        "# Visual guard for protected sandbox paths.\n"
        "# This prevents common accidents, but it is not a kernel security boundary.\n"
        "\n"
        "__sandbox_security_is_locked_path() {\n"
        "    case \"$PWD\" in\n"
        "        /data|/data/data)\n"
        "            return 0 ;;\n"
        "        /system|/system/*|/apex|/apex/*|/linkerconfig|/linkerconfig/*)\n"
        "            return 0 ;;\n"
        "        /proc|/proc/*|/sys|/sys/*|/dev|/dev/*)\n"
        "            return 0 ;;\n"
        "        /sdcard|/sdcard/*|/storage|/storage/*|/mnt|/mnt/*)\n"
        "            return 0 ;;\n"
        "    esac\n"
        "\n"
        "    return 1\n"
        "}\n"
        "\n"
        "__sandbox_security_resolve_path() {\n"
        "    case \"$1\" in\n"
        "        /*)\n"
        "            printf '%s\\n' \"$1\" ;;\n"
        "        *)\n"
        "            printf '%s/%s\\n' \"$PWD\" \"$1\" ;;\n"
        "    esac\n"
        "}\n"
        "\n"
        "__sandbox_security_canonical_path() {\n"
        "    local target\n"
        "\n"
        "    target=\"$(__sandbox_security_resolve_path \"$1\")\"\n"
        "\n"
        "    if command -v readlink >/dev/null 2>&1; then\n"
        "        readlink -f \"$target\" 2>/dev/null && return 0\n"
        "    fi\n"
        "\n"
        "    printf '%s\\n' \"$target\"\n"
        "}\n"
        "\n"
        "__sandbox_security_is_dangerous_target() {\n"
        "    local target\n"
        "\n"
        "    target=\"$(__sandbox_security_canonical_path \"$1\")\"\n"
        "\n"
        "    case \"$target\" in\n"
        "        /)\n"
        "            return 0 ;;\n"
        "        /data|/data/data)\n"
        "            return 0 ;;\n"
        "        /system|/system/*|/apex|/apex/*|/linkerconfig|/linkerconfig/*)\n"
        "            return 0 ;;\n"
        "        /proc|/proc/*|/sys|/sys/*|/dev|/dev/*)\n"
        "            return 0 ;;\n"
        "        /sdcard|/sdcard/*|/storage|/storage/*|/mnt|/mnt/*)\n"
        "            return 0 ;;\n"
        "    esac\n"
        "\n"
        "    return 1\n"
        "}\n"
        "\n"
        "__sandbox_security_check_destructive_args() {\n"
        "    local arg\n"
        "\n"
        "    for arg in \"$@\"; do\n"
        "        case \"$arg\" in\n"
        "            --)\n"
        "                continue ;;\n"
        "            -*)\n"
        "                continue ;;\n"
        "        esac\n"
        "\n"
        "        if __sandbox_security_is_dangerous_target \"$arg\"; then\n"
        "            printf 'sandbox-security: blocked destructive operation on protected path: %s 🔒\\n' \"$arg\" >&2\n"
        "            return 126\n"
        "        fi\n"
        "    done\n"
        "\n"
        "    return 0\n"
        "}\n"
        "\n"
        "rm() {\n"
        "    __sandbox_security_check_destructive_args \"$@\" || return $?\n"
        "    command rm \"$@\"\n"
        "}\n"
        "\n"
        "rmdir() {\n"
        "    __sandbox_security_check_destructive_args \"$@\" || return $?\n"
        "    command rmdir \"$@\"\n"
        "}\n"
        "\n"
        "mv() {\n"
        "    __sandbox_security_check_destructive_args \"$@\" || return $?\n"
        "    command mv \"$@\"\n"
        "}\n"
        "\n"
        "..() {\n"
        "    cd ..\n"
        "}\n"
        "\n"
        "__sandbox_security_pretty_pwd() {\n"
        "    local p=\"$PWD\"\n"
        "\n"
        "    case \"$p\" in\n"
        "        \"$HOME\")\n"
        "            p=\"~\" ;;\n"
        "        \"$HOME\"/*)\n"
        "            p=\"~${p#$HOME}\" ;;\n"
        "    esac\n"
        "\n"
        "    if __sandbox_security_is_locked_path; then\n"
        "        printf '%s🔒' \"$p\"\n"
        "    else\n"
        "        printf '%s' \"$p\"\n"
        "    fi\n"
        "}\n"
        "\n"
        "if [ -n \"$BASH_VERSION\" ]; then\n"
        "    __sandbox_security_set_bash_prompt() {\n"
        "        PS1='$(__sandbox_security_pretty_pwd) \\$ '\n"
        "    }\n"
        "\n"
        "    case \";$PROMPT_COMMAND;\" in\n"
        "        *\";__sandbox_security_set_bash_prompt;\"*) ;;\n"
        "        *) PROMPT_COMMAND=\"__sandbox_security_set_bash_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}\" ;;\n"
        "    esac\n"
        "fi\n"
        "\n"
        "if [ -n \"$ZSH_VERSION\" ]; then\n"
        "    autoload -Uz add-zsh-hook 2>/dev/null || true\n"
        "\n"
        "    __sandbox_security_set_zsh_prompt() {\n"
        "        PROMPT=\"$(__sandbox_security_pretty_pwd) %# \"\n"
        "    }\n"
        "\n"
        "    if typeset -f add-zsh-hook >/dev/null 2>&1; then\n"
        "        add-zsh-hook precmd __sandbox_security_set_zsh_prompt\n"
        "    else\n"
        "        precmd() {\n"
        "            __sandbox_security_set_zsh_prompt\n"
        "        }\n"
        "    fi\n"
        "fi\n";

    static const char hook_line[] =
        "[ -f \"$HOME/.sandbox-security.sh\" ] && . \"$HOME/.sandbox-security.sh\"";

    if (!rootfs_path || rootfs_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (asprintf(&home_dir, "%s%s", rootfs_path, TERMUX_HOME) < 0 ||
        asprintf(&guard_path, "%s%s/.sandbox-security.sh", rootfs_path, TERMUX_HOME) < 0 ||
        asprintf(&bashrc_path, "%s%s/.bashrc", rootfs_path, TERMUX_HOME) < 0 ||
        asprintf(&zshrc_path, "%s%s/.zshrc", rootfs_path, TERMUX_HOME) < 0) {
        goto out;
    }

    if (mkdir_p(home_dir, 0700) != 0) {
        goto out;
    }

    if (write_file_if_changed(guard_path, guard_script, 0600) != 0) {
        goto out;
    }

    if (append_line_if_missing(bashrc_path, ".sandbox-security.sh", hook_line) != 0) {
        goto out;
    }

    if (append_line_if_missing(zshrc_path, ".sandbox-security.sh", hook_line) != 0) {
        goto out;
    }

    ret = 0;

out:
    free(home_dir);
    free(guard_path);
    free(bashrc_path);
    free(zshrc_path);
    return ret;
}
