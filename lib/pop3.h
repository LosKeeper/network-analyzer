#pragma once
#include "verbose.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define POP3_PORT 110
#define POP3S_PORT 995

/**
 * @brief Print and analyse the POP3 packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyse
 * @param data_len the length of the packet
 * @return 1 if the function printed something, 0 otherwise
 */
int get_pop3(u_char *args, const u_char *packet, int data_len);