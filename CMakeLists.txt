cmake_minimum_required(VERSION 3.30)
project(CourseWork C)

set(CMAKE_C_STANDARD 11)

add_executable(CourseWork main.c
        config.c
        config.h
        thread_manager.c
        thread_manager.h
        monitor.c
        monitor.h
        integrity.c
        integrity.h
        logger.c
        logger.h)
