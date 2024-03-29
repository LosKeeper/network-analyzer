#pragma once
#include "verbose.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IMAP_PORT 143
#define IMAP_SSL_PORT 993

/**
 * @brief Print and analyse the IMAP packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyse
 * @param data_len the length of the packet
 * @return 1 if the function printed something, 0 otherwise
 */
int get_imap(u_char *args, const u_char *packet, int data_len);