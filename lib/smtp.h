#pragma once
#include "verbose.h"
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#define SMTP_PORT 25

/**
 * @brief Print and decode the SMTP packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyse
 * @param data_len the length of the packet
 * @return 1 if the function printed something, 0 otherwise
 */
int got_smtp(u_char *args, const u_char *packet, int data_len);