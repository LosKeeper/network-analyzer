#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Print an error message and exit the program
 *
 * @param fmt the message to print
 * @param ... the arguments of the message
 */
void panic(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    exit(EXIT_FAILURE);
}