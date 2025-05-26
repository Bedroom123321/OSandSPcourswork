#include <stdlib.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "thread_manager.h"
#include "monitor.h"
#include "logger.h"

int init_thread_manager(ThreadManager *tm, Config *config) {
    tm->config = config;
    tm->num_threads = config->num_files;
    tm->threads = malloc(tm->num_threads * sizeof(pthread_t));
    if (!tm->threads) {
        log_message(ERROR, "Не удалось выделить память для потоков");
        return 0;
    }

    // Инициализируем один экземпляр inotify
    tm->inotify_fd = inotify_init();
    if (tm->inotify_fd < 0) {
        log_message(ERROR, "Не удалось инициализировать inotify в thread_manager: %s", strerror(errno));
        free(tm->threads);
        return 0;
    }

    return 1;
}

void *monitor_thread(void *arg) {
    ThreadManager *tm = (ThreadManager *)arg;
    for (int i = 0; i < tm->num_threads; i++) {
        if (tm->inotify_fd >= 0) {
            monitor_file(tm->inotify_fd, tm->config->file_paths[i]);
        } else {
            log_message(ERROR, "inotify_fd недоступен для потока");
            break;
        }
    }
    return NULL;
}

void start_monitoring(ThreadManager *tm) {
    if (tm->inotify_fd < 0) {
        log_message(ERROR, "inotify_fd не инициализирован перед запуском потоков");
        return;
    }
    for (int i = 0; i < tm->num_threads; i++) {
        if (pthread_create(&tm->threads[i], NULL, monitor_thread, tm) != 0) {
            log_message(ERROR, "Не удалось создать поток для %s", tm->config->file_paths[i]);
        }
    }
}

void stop_thread_manager(ThreadManager *tm) {
    if (tm->inotify_fd >= 0) {
        close(tm->inotify_fd); // Закрываем inotify_fd только если он был инициализирован
    }
    for (int i = 0; i < tm->num_threads; i++) {
        pthread_cancel(tm->threads[i]);
    }
    for (int i = 0; i < tm->num_threads; i++) {
        pthread_join(tm->threads[i], NULL);
    }
    free(tm->threads);
}