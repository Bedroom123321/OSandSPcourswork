#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <grp.h>
#include "thread_manager.h"
#include "logger.h"
#include "config.h"

volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Использование: %s <корневая_директория> <имя_группы>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Получаем GID по имени группы
    struct group *grp = getgrnam(argv[2]);
    if (!grp) {
        fprintf(stderr, "Не удалось найти группу %s\n", argv[2]);
        return EXIT_FAILURE;
    }
    gid_t target_gid = grp->gr_gid;

    // Инициализация логгера
    init_logger("file_monitor.log");

    // Настройка обработки сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Загрузка конфигурации
    Config config;
    if (!load_config(argv[1], target_gid, &config)) {
        log_message(ERROR, "Не удалось загрузить конфигурацию для директории %s и группы %s", argv[1], argv[2]);
        return EXIT_FAILURE;
    }

    // Инициализация менеджера потоков
    ThreadManager tm;
    if (!init_thread_manager(&tm, &config)) {
        log_message(ERROR, "Не удалось инициализировать менеджер потоков");
        free_config(&config);
        return EXIT_FAILURE;
    }

    // Запуск мониторинга
    start_monitoring(&tm);

    // Основной цикл (ожидание сигнала для завершения)
    while (keep_running) {
        sleep(1);
    }

    // Очистка ресурсов
    stop_thread_manager(&tm);
    free_config(&config);
    close_logger();

    return EXIT_SUCCESS;
}