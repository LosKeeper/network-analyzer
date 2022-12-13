#pragma once
#include "verbose.h"
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#define TELNET_PORT 23

/**
 * @brief Print and decode a telnet packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyze
 * @param data_len the length of the packet
 * @return 1 if the function printed something, 0 otherwise
 */
int got_telnet(u_char *args, const u_char *packet, int data_len);