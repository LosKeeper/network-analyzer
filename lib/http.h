#pragma once
#include "verbose.h"
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443

/**
 * @brief Print and decode the HTTP packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyse
 * @param data_len the length of the packet
 * @return 1 if the function printed something, 0 otherwise
 */
int got_http(u_char *args, const u_char *packet, int data_len);

/**
 * @brief Print and decode the HTTPS packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyse
 * @return int 1 if the function printed something, 0 otherwise
 */
int got_https(u_char *args, const u_char *packet);
