#pragma once
#include "verbose.h"
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Print and decode the ARP packet
 *
 * @param args the verbosity level
 * @param tcp the TCP header
 */
void get_arp(u_char *args, const u_char *packet);