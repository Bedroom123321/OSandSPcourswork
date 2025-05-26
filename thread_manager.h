#ifndef THREAD_MANAGER_H
#define THREAD_MANAGER_H

#include <pthread.h>
#include "config.h"

typedef struct {
    pthread_t *threads;
    int num_threads;
    Config *config;
    int inotify_fd;
} ThreadManager;

int init_thread_manager(ThreadManager *tm, Config *config);
void start_monitoring(ThreadManager *tm);
void stop_thread_manager(ThreadManager *tm);

#endif