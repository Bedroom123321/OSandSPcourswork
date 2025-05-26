#ifndef LOGGER_H
#define LOGGER_H

typedef enum { INFO, WARNING, ERROR } LogLevel;

void init_logger(const char *log_file);
void log_message(LogLevel level, const char *format, ...);
void close_logger(void);

#endif