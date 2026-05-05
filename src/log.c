#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

void log_init(const char *sandbox_name) {
    (void)sandbox_name;
}

static void vlog_msg(const char *level, const char *fmt, va_list args) {
    time_t now = time(NULL);
    char buf[32];
    struct tm *tm = localtime(&now);

    if (tm) {
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    } else {
        snprintf(buf, sizeof(buf), "unknown-time");
    }

    fprintf(stderr, "[%s] [%s] ", buf, level ? level : "LOG");
    vfprintf(stderr, fmt ? fmt : "", args);
    fprintf(stderr, "\n");
}

void log_msg(const char *level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog_msg(level, fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog_msg("INFO", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog_msg("ERROR", fmt, args);
    va_end(args);
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog_msg("DEBUG", fmt, args);
    va_end(args);
}
