#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "logger.h"

static FILE *log_fp = NULL;

void init_logger(const char *log_file) {
    log_fp = fopen(log_file, "a");
    if (!log_fp) {
        fprintf(stderr, "Не удалось открыть лог-файл %s\n", log_file);
    }
}

void log_message(LogLevel level, const char *format, ...) {
    if (!log_fp) return;

    const char *level_str;
    switch (level) {
        case INFO: level_str = "INFO"; break;
        case WARNING: level_str = "WARNING"; break;
        case ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }

    time_t now = time(NULL);
    char time_str[26];
    ctime_r(&now, time_str);
    time_str[strcspn(time_str, "\n")] = 0;

    fprintf(log_fp, "[%s] %s: ", time_str, level_str);
    va_list args;
    va_start(args, format);
    vfprintf(log_fp, format, args);
    va_end(args);
    fprintf(log_fp, "\n");
    fflush(log_fp);
}

void close_logger(void) {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}