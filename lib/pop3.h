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

int get_pop3(u_char *args, const u_char *packet);