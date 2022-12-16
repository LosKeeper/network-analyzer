#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Print a message if the desired level is equal to the message level
 *
 * @param desired_level the desired level of verbosity
 * @param msg_level the level of the message
 * @param msg the message to print
 * @param ... the arguments to the message
 */
void print_verbosity(u_char desired_level, u_char msg_level, const char *msg,
                     ...);