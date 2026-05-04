#ifndef LOG_H
#define LOG_H

void log_init(const char *sandbox_name);
void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_debug(const char *fmt, ...);

#endif
