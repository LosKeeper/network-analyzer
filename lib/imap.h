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

int get_imap(u_char *args, const u_char *packet);