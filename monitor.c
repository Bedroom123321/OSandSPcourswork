#include <stdio.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "monitor.h"
#include "integrity.h"
#include "logger.h"
#include "config.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

void monitor_file(int inotify_fd, const char *file_path) {
    int wd = inotify_add_watch(inotify_fd, file_path, IN_MODIFY | IN_CREATE | IN_DELETE);
    if (wd < 0) {
        log_message(ERROR, "Не удалось добавить наблюдение за %s: %s", file_path, strerror(errno));
        return;
    }

    char buffer[BUF_LEN];
    while (1) {
        int length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            log_message(ERROR, "Ошибка чтения событий inotify: %s", strerror(errno));
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                if (event->mask & IN_MODIFY) {
                    char full_path[MAX_PATH];
                    snprintf(full_path, MAX_PATH, "%s/%s", file_path, event->name);
                    log_message(INFO, "Файл %s изменён", full_path);
                    check_file_integrity(full_path);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(inotify_fd, wd);
}