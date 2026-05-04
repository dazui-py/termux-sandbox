#ifndef ROOTFS_H
#define ROOTFS_H

// Get cached rootfs artifact path
char *rootfs_get_cached(void);

// Extract rootfs to destination
int rootfs_extract(const char *source, const char *dest);

// Get current architecture
const char *get_arch(void);

#endif
