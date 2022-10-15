#pragma once
#include <netinet/in.h>
#include <stdint.h>

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
 * @brief Print the bootp header
 *
 * @param bootp
 */
void print_bootp(struct bootphdr *bootp);
