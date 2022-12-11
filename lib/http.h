#pragma once
#include "verbose.h"
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#define HTTP_PORT 80

/**
 * @brief Print and decode the HTTP packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyse
 * @return 1 if the function printed something, 0 otherwise
 */
int got_http(u_char *args, const u_char *packet);
