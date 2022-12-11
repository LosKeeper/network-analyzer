#pragma once
#include "verbose.h"
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#define FTP_PORT 21

/**
 * @brief Print and analyze FTP packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyze
 * @param req 1 if the packet is a request, 0 if it is a response
 * @return 1 if the function printed something, 0 otherwise or the port for the
 * data connection
 */
int got_ftp(u_char *args, const u_char *packet, int req);

/**
 * @brief Print and analyze FTP data packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyze
 * @return 1 if the function printed something, 0 otherwise
 */
int got_ftp_data(u_char *args, const u_char *packet);