#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include "config.h"
#include "logger.h"

// Функция для проверки, является ли файл временным
int is_temporary_file(const char *filename) {
    if (strstr(filename, ".idea") != NULL || strstr(filename, "workspace.xml") != NULL) {
        return 1;
    }
    const char *ext = strrchr(filename, '.');
    if (ext && (strcmp(ext, ".tmp") == 0 || strcmp(ext, ".swp") == 0)) {
        return 1;
    }
    return 0;
}

// Функция для вычисления SHA-256 хэша файла с использованием EVP
char *compute_file_hash(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        log_message(ERROR, "Не удалось открыть файл для вычисления хэша: %s", strerror(errno));
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        log_message(ERROR, "Не удалось создать контекст EVP_MD_CTX");
        fclose(file);
        return NULL;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        log_message(ERROR, "Не удалось инициализировать контекст для SHA-256");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            log_message(ERROR, "Ошибка обновления хэша");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return NULL;
        }
    }
    fclose(file);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        log_message(ERROR, "Ошибка финализации хэша");
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }
    EVP_MD_CTX_free(mdctx);

    char *hash_str = malloc(hash_len * 2 + 1);
    if (!hash_str) {
        log_message(ERROR, "Не удалось выделить память для хэша");
        return NULL;
    }
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    hash_str[hash_len * 2] = '\0';

    return hash_str;
}

// Рекурсивная функция для поиска файлов
void traverse_directory(const char *dir_path, gid_t target_gid, Config *config) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        log_message(ERROR, "Не удалось открыть директорию %s: %s", dir_path, strerror(errno));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[PATH_MAX];
        snprintf(full_path, PATH_MAX, "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == -1) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            // Рекурсивно обходим поддиректорию
            traverse_directory(full_path, target_gid, config);
        } else if (st.st_gid == target_gid && S_ISREG(st.st_mode) && !is_temporary_file(entry->d_name)) {
            // Добавляем файл в конфигурацию
            config->num_files++;
            char **temp_paths = realloc(config->file_paths, config->num_files * sizeof(char *));
            char **temp_hashes = realloc(config->file_hashes, config->num_files * sizeof(char *));
            if (!temp_paths || !temp_hashes) {
                log_message(ERROR, "Не удалось выделить память для file_paths или file_hashes");
                free_config(config);
                return;
            }
            config->file_paths = temp_paths;
            config->file_hashes = temp_hashes;
            config->file_paths[config->num_files - 1] = strdup(full_path);
            if (!config->file_paths[config->num_files - 1]) {
                log_message(ERROR, "Не удалось выделить память для пути %s", full_path);
                free_config(config);
                return;
            }
            // Вычисляем исходный хэш
            config->file_hashes[config->num_files - 1] = compute_file_hash(full_path);
            if (!config->file_hashes[config->num_files - 1]) {
                free(config->file_paths[config->num_files - 1]);
                config->num_files--;
                continue;
            }
        }
    }

    closedir(dir);
}

int load_config(const char *root_dir, gid_t target_gid, Config *config) {
    config->root_dir = strdup(root_dir);
    if (!config->root_dir) {
        log_message(ERROR, "Не удалось выделить память для root_dir");
        return 0;
    }
    config->target_gid = target_gid;
    config->num_files = 0;
    config->file_paths = NULL;
    config->file_hashes = NULL;

    // Запускаем рекурсивный обход
    traverse_directory(root_dir, target_gid, config);

    log_message(INFO, "Найдено %d файлов для мониторинга", config->num_files);
    return config->num_files > 0;
}

void free_config(Config *config) {
    if (config->root_dir) {
        free(config->root_dir);
    }
    if (config->file_paths) {
        for (int i = 0; i < config->num_files; i++) {
            free(config->file_paths[i]);
        }
        free(config->file_paths);
    }
    if (config->file_hashes) {
        for (int i = 0; i < config->num_files; i++) {
            if (config->file_hashes[i]) {
                free(config->file_hashes[i]);
            }
        }
        free(config->file_hashes);
    }
    config->file_paths = NULL;
    config->file_hashes = NULL;
    config->num_files = 0;
    config->target_gid = 0;
}