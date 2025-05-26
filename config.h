#ifndef CONFIG_H
#define CONFIG_H

#define MAX_FILES 100
#define MAX_PATH 256

typedef struct {
    char **file_paths;
    int num_files;
    gid_t target_gid; // Идентификатор группы пользователей
    char *root_dir;   // Корневая директория для поиска
} Config;

int load_config(const char *root_dir, gid_t gid, Config *config);
void free_config(Config *config);

#endif