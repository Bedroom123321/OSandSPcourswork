# Компилятор и флаги
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpthread -lcrypto

# Имена файлов
TARGET = file_monitor
SOURCES = main.c config.c thread_manager.c integrity.c logger.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = config.h thread_manager.h monitor.h integrity.h logger.h

# Цель по умолчанию: сборка программы
all: $(TARGET)

# Сборка исполняемого файла из объектных файлов
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Компиляция исходных файлов в объектные
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Очистка сгенерированных файлов
clean:
	rm -f $(OBJECTS) $(TARGET)

# Запуск программы
run: $(TARGET)
	./$(TARGET)

# Указание, что эти цели не являются файлами
.PHONY: all clean run