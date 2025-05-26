#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <grp.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "thread_manager.h"
#include "monitor.h"
#include "integrity.h"
#include "logger.h"
#include "config.h"

volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
}

void display_menu() {
    printf("\n=== Меню программы мониторинга ===\n");
    printf("1. Начать мониторинг\n");
    printf("2. Остановить мониторинг\n");
    printf("3. Проверить статус\n");
    printf("4. Просмотреть отслеживаемые файлы\n");
    printf("5. Просмотреть файл логов\n");
    printf("6. Установить путь и группу\n");
    printf("7. Выход\n");
    printf("8. Очистить файл логов\n");
    printf("Выберите действие (1-8): ");
}

int is_monitoring_running(const char *pid_file, pid_t *pid) {
    FILE *fp = fopen(pid_file, "r");
    if (!fp) return 0;
    if (fscanf(fp, "%d", pid) != 1) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    if (kill(*pid, 0) == 0) return 1;
    remove(pid_file);
    return 0;
}

void stop_monitoring_process(const char *pid_file) {
    FILE *fp = fopen(pid_file, "r");
    if (!fp) return;
    pid_t pid;
    if (fscanf(fp, "%d", &pid) == 1) {
        kill(pid, SIGTERM);
        log_message(INFO, "Отправлен сигнал остановки процессу с PID %d", pid);
    }
    fclose(fp);
    remove(pid_file);
}

int main(int argc, char *argv[]) {
    init_logger("file_monitor.log");
    log_message(INFO, "Программа запущена");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    Config config = {0};
    ThreadManager tm = {0};
    int monitoring_started = 0;
    char root_dir[PATH_MAX] = {0};
    char group_name[256] = {0};
    gid_t target_gid = 0;
    const char *pid_file = "./file_monitor.pid";
    const char *config_file = "monitor_config.txt";
    pid_t monitor_pid = 0;

    // Читаем конфигурацию, если она есть
    FILE *cf = fopen(config_file, "r");
    if (cf) {
        if (fscanf(cf, "%s %s", root_dir, group_name) == 2) {
            struct group *grp = getgrnam(group_name);
            if (grp) target_gid = grp->gr_gid;
            log_message(INFO, "Загружена конфигурация: путь %s, группа %s", root_dir, group_name);
        }
        fclose(cf);
    }

    // Проверяем, запущен ли мониторинг
    if (is_monitoring_running(pid_file, &monitor_pid)) {
        monitoring_started = 1;
        log_message(INFO, "Обнаружен запущенный мониторинг с PID %d", monitor_pid);
    }

    while (keep_running) {
        display_menu();
        int choice;
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                if (!monitoring_started) {
                    if (strlen(root_dir) == 0 || target_gid == 0) {
                        printf("Сначала установите путь и группу (опция 6).\n");
                        break;
                    }
                    if (!load_config(root_dir, target_gid, &config)) {
                        log_message(WARNING, "Не найдено файлов для мониторинга в директории %s для группы %s", root_dir, group_name);
                        break;
                    }
                    if (!init_thread_manager(&tm, &config)) {
                        log_message(ERROR, "Не удалось инициализировать менеджер потоков");
                        free_config(&config);
                        break;
                    }

                    // Запуск в фоновом режиме
                    pid_t pid = fork();
                    if (pid < 0) {
                        log_message(ERROR, "Ошибка при создании процесса: %s", strerror(errno));
                        free_config(&config);
                        break;
                    }
                    if (pid == 0) {
                        // Дочерний процесс
                        start_monitoring(&tm);
                        log_message(INFO, "Мониторинг запущен для %d файлов", config.num_files);
                        while (keep_running) {
                            sleep(1);
                        }
                        stop_thread_manager(&tm);
                        free_config(&config);
                        log_message(INFO, "Мониторинг завершён");
                        close_logger();
                        exit(EXIT_SUCCESS);
                    } else {
                        // Родительский процесс
                        FILE *pf = fopen(pid_file, "w");
                        if (pf) {
                            fprintf(pf, "%d\n", pid);
                            fclose(pf);
                        }
                        monitoring_started = 1;
                        monitor_pid = pid;
                        log_message(INFO, "Мониторинг запущен в фоновом режиме с PID %d", pid);
                        printf("Мониторинг начат в фоновом режиме. PID: %d.\n", pid);
                    }
                } else {
                    printf("Мониторинг уже запущен.\n");
                }
                break;

            case 2:
                if (is_monitoring_running(pid_file, &monitor_pid)) {
                    stop_monitoring_process(pid_file);
                    monitoring_started = 0;
                    monitor_pid = 0;
                    free_config(&config);
                    log_message(INFO, "Мониторинг остановлен");
                    printf("Мониторинг остановлен.\n");
                } else {
                    printf("Мониторинг не запущен.\n");
                    monitoring_started = 0;
                    monitor_pid = 0;
                }
                break;

            case 3:
                if (is_monitoring_running(pid_file, &monitor_pid)) {
                    monitoring_started = 1;
                    printf("Мониторинг активен (PID: %d).\n", monitor_pid);
                } else {
                    monitoring_started = 0;
                    monitor_pid = 0;
                    printf("Мониторинг не активен.\n");
                }
                break;

            case 4:
                if (config.num_files > 0) {
                    printf("\nОтслеживаемые файлы:\n");
                    for (int i = 0; i < config.num_files; i++) {
                        printf("%s\n", config.file_paths[i]);
                    }
                } else {
                    printf("Нет отслеживаемых файлов. Установите путь и группу (опция 6).\n");
                }
                break;

            case 5:
                printf("Просмотр файла логов (file_monitor.log):\n");
                system("cat file_monitor.log");
                break;

            case 6:
                if (monitoring_started && is_monitoring_running(pid_file, &monitor_pid)) {
                    printf("Остановите мониторинг перед изменением пути и группы.\n");
                    break;
                }
                printf("Введите путь к директории: ");
                scanf("%s", root_dir);
                printf("Введите имя группы: ");
                scanf("%s", group_name);
                struct group *grp = getgrnam(group_name);
                if (!grp) {
                    printf("Не удалось найти группу %s\n", group_name);
                    root_dir[0] = '\0';
                    group_name[0] = '\0';
                    break;
                }
                target_gid = grp->gr_gid;
                cf = fopen(config_file, "w");
                if (cf) {
                    fprintf(cf, "%s %s\n", root_dir, group_name);
                    fclose(cf);
                }
                log_message(INFO, "Установлены путь %s и группа %s", root_dir, group_name);
                printf("Путь и группа успешно установлены.\n");
                break;

            case 7:
                // Проверяем, активен ли мониторинг
                if (!is_monitoring_running(pid_file, &monitor_pid)) {
                    // Если мониторинг не активен, очищаем monitor_config.txt
                    FILE *cfg = fopen(config_file, "w");
                    if (cfg) {
                        fclose(cfg);
                        log_message(INFO, "Файл конфигурации %s очищен при выходе", config_file);
                    } else {
                        log_message(ERROR, "Не удалось очистить файл конфигурации %s: %s", config_file, strerror(errno));
                    }
                } else {
                    log_message(WARNING, "Мониторинг всё ещё активен, файл конфигурации %s не очищен", config_file);
                }
                log_message(INFO, "Выход из программы");
                close_logger();
                return EXIT_SUCCESS;

            case 8:
                // Очистка файла логов
            {
                FILE *log_file = fopen("file_monitor.log", "w");
                if (log_file) {
                    fclose(log_file);
                    printf("Файл логов file_monitor.log очищен.\n");
                    // Инициализируем логгер заново, чтобы продолжить логирование
                    init_logger("file_monitor.log");
                    log_message(INFO, "Файл логов очищен");
                } else {
                    printf("Не удалось очистить файл логов: %s\n", strerror(errno));
                    log_message(ERROR, "Не удалось очистить файл логов: %s", strerror(errno));
                }
            }
                break;

            default:
                printf("Неверный выбор. Введите число от 1 до 8.\n");
        }
    }

    close_logger();
    return EXIT_SUCCESS;
}