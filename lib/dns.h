#pragma once
#include <stdint.h>

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
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    struct in_addr rdata;
};