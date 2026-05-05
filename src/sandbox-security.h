#ifndef SANDBOX_SECURITY_H
#define SANDBOX_SECURITY_H

/* sandbox-security: visual/policy-adjacent hardening helpers. */
int sandbox_security_install(const char *rootfs_path);
int sandbox_security_path_is_protected(const char *path);
int sandbox_security_path_is_allowed(const char *path);

#endif
