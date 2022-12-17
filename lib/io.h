#pragma once
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Structure to store the arguments of the program
 *
 */
typedef struct args {
    char *interface;
    char *file;
    char *filter;
    u_char verbose;
} args_s;

/**
 * @brief Print usage of the program
 *
 * @param progname the name of the program
 */
void print_usage(const char *progname);

/**
 * @brief Parse arguments of the program
 *
 * @param argc the number of arguments
 * @param argv the arguments
 * @param argument the structure to store the arguments
 */
void parse_args(int argc, char **argv, args_s *argument);

/**
 * @brief Check if the given arguments are valid
 *
 * @param argument the structure in which are store the arguments
 */
void validity_check(args_s *argument);
