#ifndef CONFIG_H
#define CONFIG_H

#include <sys/types.h>

#define PATH_MAX 4096

typedef struct {
    char *root_dir;
    gid_t target_gid;
    int num_files;
    char **file_paths;
    char **file_hashes; // Массив для хранения исходных хэшей файлов
} Config;

int load_config(const char *root_dir, gid_t target_gid, Config *config);
void free_config(Config *config);

#endif