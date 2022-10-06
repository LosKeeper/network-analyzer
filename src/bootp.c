#include "bootp.h"

char *get_vendor_type(uint8_t type) {
    switch (type) {
    case 0:
        return "Pad";
    case 1:
        return "Subnet Mask";
    case 2:
        return "Time Offset";
    case 3:
        return "Router";
    case 6:
        return "Domain Name Server";
    case 12:
        return "Host Name";
    case 15:
        return "Domain Name";
    case 28:
        return "Broadcast Address";
    case 44:
        return "NetBIOS over TCP/IP Name Server";
    case 47:
        return "NetBIOS over TCP/IP Scope";
    case 50:
        return "Requested IP Address";
    case 51:
        return "IP Address Lease Time";
    case 53:
        return "DHCP Message Type";
    case 54:
        return "DHCP Server Identifier";
    case 55:
        return "Parameter Request List";
    }
    return "Unknown";
}