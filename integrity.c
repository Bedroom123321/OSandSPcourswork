#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "integrity.h"
#include "logger.h"

void check_file_integrity(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        log_message(ERROR, "Не удалось открыть файл %s", file_path);
        return;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[8192];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    fclose(file);

    char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }

    // Для простоты логируем хеш (в продакшене нужно сравнивать с сохранённым хешем)
    log_message(INFO, "Хеш файла %s: %s", file_path, hash_str);
}