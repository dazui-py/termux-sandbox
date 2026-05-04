#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

void log_init(const char *sandbox_name) {
    // No-op for now, will be used when log path is configured
}

void log_msg(const char *level, const char *fmt, ...) {
    time_t now = time(NULL);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[%s] [%s] ", buf, level);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg("INFO", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg("ERROR", fmt, args);
    va_end(args);
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg("DEBUG", fmt, args);
    va_end(args);
}
