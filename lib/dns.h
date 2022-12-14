#pragma once
#include "verbose.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DNS_PORT 53

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dnsquestion {
    uint16_t qtype;
    uint16_t qclass;
};

struct dnsanswer {
    uint16_t name;
    uint16_t type;
    uint16_t class;
    uint16_t ttl;
    uint8_t nothing;
    uint16_t rdlength;
};

int got_dns(u_char *args, const u_char *packet, int data_len);