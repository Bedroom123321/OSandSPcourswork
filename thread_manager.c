#include <stdlib.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/evp.h> // Новый заголовок для EVP API
#include "thread_manager.h"
#include "monitor.h"
#include "integrity.h"
#include "logger.h"

// Структура для хранения соответствия watch descriptor (wd), пути файла и исходного хэша
typedef struct {
    int wd;
    char *file_path;
    char *original_hash;
} WatchEntry;

int init_thread_manager(ThreadManager *tm, Config *config) {
    tm->config = config;
    tm->num_threads = 1; // Один поток для всех файлов
    tm->threads = malloc(tm->num_threads * sizeof(pthread_t));
    if (!tm->threads) {
        log_message(ERROR, "Не удалось выделить память для потоков");
        return 0;
    }

    tm->inotify_fd = inotify_init1(IN_NONBLOCK);
    if (tm->inotify_fd < 0) {
        log_message(ERROR, "Не удалось инициализировать inotify в thread_manager: %s", strerror(errno));
        free(tm->threads);
        return 0;
    }

    // Проверка лимита inotify
    FILE *limit_file = fopen("/proc/sys/fs/inotify/max_user_watches", "r");
    if (limit_file) {
        int max_watches;
        if (fscanf(limit_file, "%d", &max_watches) == 1) {
            if (max_watches < tm->config->num_files) {
                log_message(WARNING, "Лимит inotify (max_user_watches = %d) меньше количества файлов (%d). Увеличьте лимит командой: sudo sysctl -w fs.inotify.max_user_watches=%d", max_watches, tm->config->num_files, tm->config->num_files * 2);
            }
        }
        fclose(limit_file);
    }

    return 1;
}

void *monitor_thread(void *arg) {
    ThreadManager *tm = (ThreadManager *)arg;
    if (tm->inotify_fd < 0) {
        log_message(ERROR, "inotify_fd недоступен для потока");
        return NULL;
    }

    WatchEntry *watches = malloc(tm->config->num_files * sizeof(WatchEntry));
    if (!watches) {
        log_message(ERROR, "Не удалось выделить память для watches");
        return NULL;
    }

    for (int i = 0; i < tm->config->num_files; i++) {
        int wd = inotify_add_watch(tm->inotify_fd, tm->config->file_paths[i], IN_MODIFY);
        if (wd < 0) {
            log_message(ERROR, "Не удалось добавить наблюдение: %s", strerror(errno));
        } else {
            watches[i].wd = wd;
            watches[i].file_path = tm->config->file_paths[i];
            watches[i].original_hash = tm->config->file_hashes[i];
        }
    }

    char buffer[BUF_LEN];
    while (1) {
        int length = read(tm->inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000);
                continue;
            }
            log_message(ERROR, "Ошибка чтения событий inotify: %s", strerror(errno));
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->mask & IN_MODIFY) {
                for (int j = 0; j < tm->config->num_files; j++) {
                    if (watches[j].wd == event->wd) {
                        log_message(INFO, "Обнаружено изменение файла: %s", watches[j].file_path);
                        check_file_integrity(watches[j].file_path, watches[j].original_hash);
                        // Обновляем хэш после изменения
                        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                        if (mdctx) {
                            FILE *file = fopen(watches[j].file_path, "rb");
                            if (file) {
                                if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1) {
                                    unsigned char buffer[4096];
                                    size_t bytes;
                                    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
                                        EVP_DigestUpdate(mdctx, buffer, bytes);
                                    }
                                    unsigned char hash[EVP_MAX_MD_SIZE];
                                    unsigned int hash_len;
                                    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) == 1) {
                                        char *new_hash = malloc(hash_len * 2 + 1);
                                        if (new_hash) {
                                            for (unsigned int k = 0; k < hash_len; k++) {
                                                sprintf(&new_hash[k * 2], "%02x", hash[k]);
                                            }
                                            new_hash[hash_len * 2] = '\0';
                                            free(tm->config->file_hashes[j]);
                                            tm->config->file_hashes[j] = new_hash;
                                            watches[j].original_hash = new_hash;
                                        }
                                    }
                                }
                                fclose(file);
                            }
                            EVP_MD_CTX_free(mdctx);
                        }
                        inotify_rm_watch(tm->inotify_fd, watches[j].wd);
                        watches[j].wd = inotify_add_watch(tm->inotify_fd, watches[j].file_path, IN_MODIFY);
                        if (watches[j].wd < 0) {
                            log_message(ERROR, "Ошибка добавления watch: %s", strerror(errno));
                        }
                        break;
                    }
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    free(watches);
    return NULL;
}

void start_monitoring(ThreadManager *tm) {
    if (tm->inotify_fd < 0) {
        log_message(ERROR, "inotify_fd не инициализирован перед запуском потоков");
        return;
    }
    if (pthread_create(&tm->threads[0], NULL, monitor_thread, tm) != 0) {
        log_message(ERROR, "Не удалось создать поток");
    }
}

void stop_thread_manager(ThreadManager *tm) {
    if (tm->inotify_fd >= 0) {
        close(tm->inotify_fd);
    }
    if (tm->num_threads > 0) {
        pthread_cancel(tm->threads[0]);
        pthread_join(tm->threads[0], NULL);
    }
    free(tm->threads);
}