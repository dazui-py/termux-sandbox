#ifndef PATHS_H
#define PATHS_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>

// Get base directory for all sandboxes
const char *sandbox_get_base_dir(void);

// Get boxes directory
const char *sandbox_get_boxes_dir(void);

// Get cache directory
const char *sandbox_get_cache_dir(void);

// Get config directory
const char *sandbox_get_config_dir(void);

// Get path to a specific sandbox
char *sandbox_get_path(const char *name);

// Get rootfs path for a sandbox
char *sandbox_get_rootfs_path(const char *name);

// Get metadata file path
char *sandbox_get_metadata_path(const char *name);

// Get policy file path
char *sandbox_get_policy_path(const char *name);

// Get grants file path
char *sandbox_get_grants_path(const char *name);

// Get logs directory path
char *sandbox_get_logs_path(const char *name);

// Check if sandbox exists
int sandbox_exists(const char *name);

// Ensure base directories exist
void sandbox_ensure_dirs(void);

// Validate sandbox name
int sandbox_validate_name(const char *name);

// mkdir -p equivalent
void mkdir_p(const char *path, mode_t mode);

#endif
