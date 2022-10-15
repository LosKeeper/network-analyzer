#include "bootp.h"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>

#define SUBNET_MASK 1
#define ROUTER 3
#define DNS 6
#define HOSTNAME 12
#define DOMAINNAME 15
#define BROADCAST 28
#define NETBIOS_NS 44
#define NETBIOS_SCOPE 47
#define REQUESTED_IP 50
#define LEASE_TIME 51
#define MESSAGE_TYPE 53
#define SERVER_ID 54
#define PARAMETER_LIST 55
#define END 255

char *get_vendor_type(uint8_t type) {
    // TODO: Change for define
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
    case 255:
        return "End";
    }
    return "Unknown";
}

void print_bootp(struct bootphdr *bootp) {

    printf("Type : %d, htype : %d, hlen : %d, hops : %d, "
           "transaction id : %u, Delay : %d, Flags : %d, Adresse "
           "IP client : %s, Your adresse IP  : %s, Adresse de Gateway "
           ": %s, Adresse MAC source "
           ": %s, Adresse MAC client : %s, Fichier de boot : %s, Nom "
           "du serveur : %s\n",
           bootp->op, bootp->htype, bootp->hlen, bootp->hops, bootp->xid,
           bootp->secs, bootp->flags, inet_ntoa(bootp->ciaddr),
           inet_ntoa(bootp->yiaddr), inet_ntoa(bootp->siaddr),
           inet_ntoa(bootp->giaddr),
           ether_ntoa((struct ether_addr *)bootp->chaddr), bootp->file,
           bootp->sname);
}