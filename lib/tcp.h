#pragma once
#include "verbose.h"
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Print the TCP flags
 *
 * @param args the verbosity level
 * @param tcp the TCP header
 */
void get_tcp(u_char *args, struct tcphdr *tcp);