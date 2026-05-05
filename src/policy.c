#include "policy.h"

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
