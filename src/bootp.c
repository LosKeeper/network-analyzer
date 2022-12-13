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
    case 57:
        return "Maximum DHCP Message Size";
    case 58:
        return "Renewal Time Value";
    case 59:
        return "Rebinding Time Value";
    case 60:
        return "Vendor Class Identifier";
    case 61:
        return "Client Identifier";
    case 66:
        return "TFTP Server Name";
    case 67:
        return "Boot File Name";
    case 82:
        return "Agent Information Option";
    case 90:
        return "Authentication";
    case 120:
        return "SIP Servers DHCP Option";
    case 128:
        return "PXE - Client System Architecture";
    case 129:
        return "PXE - Client Network Interface Identifier";
    case 130:
        return "PXE - UEFI Device Path";
    case 131:
        return "PXE - UEFI Boot Loader Path";
    case 132:
        return "PXE - UEFI Boot Loader Server";
    case 133:
        return "PXE - UEFI Boot Loader Server Port";
    case 134:
        return "PXE - UEFI Boot Loader Server Path";
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
    struct bootphdr *bootp = (struct bootphdr *)(packet);
    packet += sizeof(struct bootphdr);

    // Verbose 0
    print_verbosity(*args, 0, "BOOTP\t\t\t\t");

    // Verbose 1
    print_verbosity(*args, 1, "\033[32m");
    print_verbosity(*args, 1, "BOOTP : ");
    print_verbosity(*args, 1, "\033[0m");
    print_verbosity(
        *args, 1,
        "Type : %d, htype : %d, hlen : %d, hops : %d, "
        "transaction id : %u, Delay : %d, Flags : %d, Client IP "
        "address : %s, Your IP address  : %s, Server IP address : "
        "%s, Gateway IP address : %s, "
        "Client MAC address : %s, Boot file name : %s, Server host name : %s\n",
        bootp->op, bootp->htype, bootp->hlen, bootp->hops, bootp->xid,
        bootp->secs, bootp->flags, inet_ntoa(bootp->ciaddr),
        inet_ntoa(bootp->yiaddr), inet_ntoa(bootp->siaddr),
        inet_ntoa(bootp->giaddr),
        ether_ntoa((struct ether_addr *)bootp->chaddr), bootp->file,
        bootp->sname);

    // Get the DHCP message type
    struct vendorhdr *vendor = (struct vendorhdr *)(packet);
    packet += sizeof(struct vendorhdr);
    // packet += vendor->len;
    switch (*args) {
    case 0:
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
            packet += vendor->len;
            vendor = (struct vendorhdr *)(packet);
            packet += sizeof(struct vendorhdr);
        }

    case 1:
        // Get all the vendor options
        while (vendor->type != 255) {
            print_verbosity(*args, 1, "\033[32m");
            print_verbosity(*args, 1, "\tVendor : ");
            print_verbosity(*args, 1, "\033[0m");
            print_verbosity(*args, 1, "%s -> ", get_vendor_type(vendor->type));
            char *data = malloc(vendor->len);
            memcpy(data, packet, vendor->len);
            switch (vendor->type) {
            case 1:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 2:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 3:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 6:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 12:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 15:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 28:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 44:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 47:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 50:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 51:
                print_verbosity(*args, 1, "%d\n", *(uint32_t *)data);
                break;
            case 53:
                print_verbosity(*args, 1, "%d\n", *(uint8_t *)data);
                break;
            case 54:
                print_verbosity(*args, 1, "%s\n",
                                inet_ntoa(*(struct in_addr *)data));
                break;
            case 55:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 57:
                print_verbosity(*args, 1, "%d\n", *(uint16_t *)data);
                break;
            case 58:
                print_verbosity(*args, 1, "%d\n", *(uint32_t *)data);
                break;
            case 59:
                print_verbosity(*args, 1, "%d\n", *(uint32_t *)data);
                break;
            case 60:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 61:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 66:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 67:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 81:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 82:
                switch (data[0]) {
                case 1:
                    print_verbosity(*args, 1, "Agent Circuit ID : %s\n",
                                    (data + 2));
                    break;
                case 2:
                    print_verbosity(*args, 1, "Agent Remote ID : %s\n",
                                    (data + 2));
                    break;
                }
                break;
            case 90:
                print_verbosity(*args, 1, "\n");
                break;
            case 120:
                // IPv4 case
                if (data[0] == 1) {
                    print_verbosity(*args, 1, "%s\n",
                                    inet_ntoa(*(struct in_addr *)(data + 1)));
                } else {
                    // IPv6 case
                    print_verbosity(*args, 1, "%s\n", (data + 1));
                }
                break;
            case 128:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 129:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 130:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 131:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 132:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 133:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 134:
                print_verbosity(*args, 1, "%s\n", data);
                break;
            case 255:
                break;
            }
            free(data);
            packet += vendor->len;
            vendor = (struct vendorhdr *)(packet);
            packet += sizeof(struct vendorhdr);
        }
    }
    return 1;
}