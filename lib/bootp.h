#pragma once
#include "verbose.h"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BOOTP_PORT_CLIENT 68
#define BOOTP_PORT_SERVER 67

/**
 * @brief The bootp header
 *
 */
struct bootphdr {
    uint8_t op;             // 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t htype;          // hardware address type
    uint8_t hlen;           // hardware address length
    uint8_t hops;           // used by relay agents
    uint32_t xid;           // transaction ID
    uint16_t secs;          // seconds since client started trying to boot
    uint16_t flags;         // flags
    struct in_addr ciaddr;  // client IP address
    struct in_addr yiaddr;  // your (client) IP address
    struct in_addr siaddr;  // server IP address
    struct in_addr giaddr;  // gateway IP address
    uint8_t chaddr[16];     // client hardware address
    uint8_t sname[64];      // server host name
    uint8_t file[128];      // boot file name
    uint8_t magicCookie[4]; // magic cookie
};

/**
 * @brief The vendor header
 *
 */
struct vendorhdr {
    uint8_t type; // type
    uint8_t len;  // length
};

/**
 * @brief Get the vendor type object
 *
 * @param type
 * @return The string representation of the vendor type
 */
char *get_vendor_type(uint8_t type);

/**
 * @brief Print and analyze the bootp packet
 *
 * @param args the verbosity level
 * @param packet the packet to analyze
 * @return 1 if the function printed something, 0 otherwise
 */
int got_bootp(u_char *args, const u_char *packet);