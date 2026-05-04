#include "policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void policy_write_default(const char *path, const char *profile) {
    FILE *fp = fopen(path, "w");
    if (!fp) return;

    if (strcmp(profile, "strict") == 0) {
        fprintf(fp, "# Strict profile - maximum isolation\n");
        fprintf(fp, "allow_sdcard=no\n");
        fprintf(fp, "allow_host_home=no\n");
        fprintf(fp, "allow_host_prefix=no\n");
        fprintf(fp, "external_mounts=no\n");
        fprintf(fp, "egress_default=deny\n");
        fprintf(fp, "logs=yes\n");
    } else {
        // default: dev profile
        fprintf(fp, "# Dev profile - project testing\n");
        fprintf(fp, "allow_sdcard=no\n");
        fprintf(fp, "allow_host_home=no\n");
        fprintf(fp, "allow_host_prefix=no\n");
        fprintf(fp, "workspace_mount=optional\n");
        fprintf(fp, "logs=yes\n");
        fprintf(fp, "egress_default=allow_granted\n");
    }

    fclose(fp);
}

int policy_load(const char *path, policy_t *policy) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    // Initialize defaults
    policy->allow_sdcard = 0;
    policy->allow_host_home = 0;
    policy->allow_host_prefix = 0;
    policy->external_mounts = 0;
    policy->workspace_mount = 0;
    policy->logs = 1;
    policy->egress_default = EGRESS_DENY;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "allow_sdcard=", 13) == 0)
            policy->allow_sdcard = strstr(line, "yes") != NULL;
        else if (strncmp(line, "allow_host_home=", 16) == 0)
            policy->allow_host_home = strstr(line, "yes") != NULL;
        else if (strncmp(line, "allow_host_prefix=", 18) ==0)
            policy->allow_host_prefix = strstr(line, "yes") != NULL;
        else if (strncmp(line, "external_mounts=", 16) == 0)
            policy->external_mounts = strstr(line, "yes") != NULL;
        else if (strncmp(line, "workspace_mount=", 16) == 0)
            policy->workspace_mount = strstr(line, "yes") != NULL;
        else if (strncmp(line, "logs=", 5) == 0)
            policy->logs = strstr(line, "yes") != NULL;
        else if (strncmp(line, "egress_default=", 15) == 0) {
            if (strstr(line, "allow")) policy->egress_default = EGRESS_ALLOW;
            else if (strstr(line, "allow_granted")) policy->egress_default = EGRESS_ALLOW_GRANTED;
            else policy->egress_default = EGRESS_DENY;
        }
    }

    fclose(fp);
    return 0;
}
