#include "bootp.h"

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

int got_bootp(u_char *args, const u_char *packet) {
    // struct bootphdr *bootp = (struct bootphdr *)(packet);
    packet += sizeof(struct bootphdr);
    print_verbosity(*args, 0, "BOOTP\t\t\t\t");
    // Get the DHCP message type
    struct vendorhdr *vendor = (struct vendorhdr *)(packet);
    packet += sizeof(struct vendorhdr);
    // Check if the packet is a DHCP packet
    while (vendor->type != 255) {
        if (vendor->type == 53) {
            print_verbosity(*args, 0, "DHCP -> ");
            // Get the DHCP message type
            switch (*(packet)) {
            case 1:
                print_verbosity(*args, 0, "Discover\t\t\t");
                break;
            case 2:
                print_verbosity(*args, 0, "Offer\t\t\t\t");
                break;
            case 3:
                print_verbosity(*args, 0, "Request\t\t\t\t");
                break;
            case 4:
                print_verbosity(*args, 0, "Decline\t\t\t\t");
                break;
            case 5:
                print_verbosity(*args, 0, "Ack\t\t\t\t");
                break;
            case 6:
                print_verbosity(*args, 0, "Nack\t\t\t\t");
                break;
            case 7:
                print_verbosity(*args, 0, "Release\t\t\t\t");
                break;
            case 8:
                print_verbosity(*args, 0, "Inform\t\t\t\t");
                break;
            }
        }
        vendor = (struct vendorhdr *)(packet);
        packet += sizeof(struct vendorhdr);
        packet += vendor->len;
    }
    return 1;
}