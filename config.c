#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "config.h"
#include "logger.h"

void scan_directory(const char *dir_path, gid_t target_gid, Config *config) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        log_message(ERROR, "Не удалось открыть директорию %s", dir_path);
        return;
    }

    struct dirent *entry;
    struct stat file_stat;
    char full_path[MAX_PATH];

    while ((entry = readdir(dir)) != NULL && config->num_files < MAX_FILES) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, MAX_PATH, "%s/%s", dir_path, entry->d_name);

        if (lstat(full_path, &file_stat) == -1) {
            log_message(WARNING, "Не удалось получить информацию о %s", full_path);
            continue;
        }

        // Проверяем, является ли файл обычным файлом и принадлежит ли нужной группе
        if (S_ISREG(file_stat.st_mode) && file_stat.st_gid == target_gid) {
            config->file_paths[config->num_files] = strdup(full_path);
            config->num_files++;
        }

        // Рекурсивный обход, если это директория
        if (S_ISDIR(file_stat.st_mode)) {
            scan_directory(full_path, target_gid, config);
        }
    }

    closedir(dir);
}

int load_config(const char *root_dir, gid_t target_gid, Config *config) {
    config->file_paths = malloc(MAX_FILES * sizeof(char *));
    if (!config->file_paths) {
        return 0;
    }
    config->num_files = 0;
    config->target_gid = target_gid;
    config->root_dir = strdup(root_dir);

    scan_directory(root_dir, target_gid, config);
    return config->num_files > 0;
}

void free_config(Config *config) {
    for (int i = 0; i < config->num_files; i++) {
        free(config->file_paths[i]);
    }
    free(config->file_paths);
    free(config->root_dir);
}