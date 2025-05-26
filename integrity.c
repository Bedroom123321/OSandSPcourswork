#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>
#include "integrity.h"
#include "logger.h"

void check_file_integrity(const char *file_path, const char *original_hash) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        log_message(ERROR, "Не удалось открыть файл для проверки целостности: %s", strerror(errno));
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        log_message(ERROR, "Не удалось создать контекст EVP_MD_CTX");
        fclose(file);
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        log_message(ERROR, "Не удалось инициализировать контекст для SHA-256");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            log_message(ERROR, "Ошибка обновления хэша");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return;
        }
    }
    fclose(file);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        log_message(ERROR, "Ошибка финализации хэша");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    EVP_MD_CTX_free(mdctx);

    // Используем hash_len для определения размера массива (SHA-256 всегда 32 байта, но так универсальнее)
    char hash_str[hash_len * 2 + 1];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    hash_str[hash_len * 2] = '\0';

    // Сравниваем новый хэш с исходным
    if (strcmp(hash_str, original_hash) == 0) {
        log_message(INFO, "Целостность файла сохранена. Хэш: %s", hash_str);
    } else {
        log_message(WARNING, "Целостность файла нарушена! Новый хэш: %s, исходный хэш: %s", hash_str, original_hash);
    }
}