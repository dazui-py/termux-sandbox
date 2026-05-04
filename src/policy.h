#ifndef POLICY_H
#define POLICY_H

typedef enum {
    EGRESS_DENY,
    EGRESS_ALLOW,
    EGRESS_ALLOW_GRANTED
} egress_mode_t;

typedef struct {
    int allow_sdcard;
    int allow_host_home;
    int allow_host_prefix;
    int external_mounts;
    int workspace_mount;
    int logs;
    egress_mode_t egress_default;
} policy_t;

void policy_write_default(const char *path, const char *profile);

int policy_load(const char *path, policy_t *policy);

#endif
