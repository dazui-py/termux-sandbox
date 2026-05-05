#ifndef ROOTFS_H
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
