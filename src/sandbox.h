#ifndef SANDBOX_H
#define SANDBOX_H

int cmd_create(int argc, char *argv[]);
int cmd_enter(int argc, char *argv[]);
int cmd_run(int argc, char *argv[]);
int cmd_list(int argc, char *argv[]);
int cmd_info(int argc, char *argv[]);
int cmd_destroy(int argc, char *argv[]);

// Execute command in proot environment
int sandbox_exec_proot(const char *name, char **cmd);

// Get current architecture
const char *get_arch(void);

#endif
