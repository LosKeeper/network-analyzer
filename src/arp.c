#include "arp.h"

void get_arp(u_char *args, const u_char *packet) {
    // On recupere les addresses
    char *src_ip = malloc(21);
    char *dst_ip = malloc(21);
    char *src_mac = malloc(18);
    char *dst_mac = malloc(18);

    int i = 0;
    int j = 0;
    while (i < 24) {
        // Convert hexa to string
        sprintf(src_mac + i, "%x", packet[j + 8]);
        sprintf(src_mac + i++, "%02x", packet[j + 8]);
        i++;
        src_mac[i] = ':';
        i++;
        j++;
    }
    src_mac[17] = '\0';
    i = 0;
    j = 0;
    while (j < 4) {
        sprintf(src_ip + i, "%d", packet[j + 14]);
        if (packet[j + 14] >= 10) {
            i++;
        }
        if (packet[j + 14] >= 100) {
            i++;
        }
        i++;
        if (j < 3) {
            src_ip[i] = '.';
        }
        i++;
        j++;
    }
    src_ip[15] = '\0';
    i = 0;
    j = 0;
    while (i < 24) {
        // Convert hexa to string
        sprintf(dst_mac + i, "%x", packet[j + 18]);
        sprintf(dst_mac + i++, "%02x", packet[j + 18]);
        i++;
        dst_mac[i] = ':';
        i++;
        j++;
    }
    dst_mac[17] = '\0';
    i = 0;
    j = 0;
    while (j < 4) {
        sprintf(dst_ip + i, "%d", packet[j + 14]);
        if (packet[j + 14] >= 10) {
            i++;
        }
        if (packet[j + 14] >= 100) {
            i++;
        }
        i++;
        if (j < 3) {
            dst_ip[i] = '.';
        }
        i++;
        j++;
    }
    dst_ip[15] = '\0';

    // Verbose 0
    print_verbosity(*args, 0, "%s\t\t\t", src_mac);
    print_verbosity(*args, 0, "%s\t\t\t", dst_mac);
    print_verbosity(*args, 0, "ARP\t\t\t\t");

    // Verbose 1
    print_verbosity(*args, 1, "\033[32m");
    print_verbosity(*args, 1, "ARP : ");
    print_verbosity(*args, 1, "\033[0m");
    print_verbosity(*args, 1, "from %s", src_mac);
    print_verbosity(*args, 1, " to %s ", dst_mac);
    if (packet[8] == 0x01) {
        print_verbosity(*args, 0, "Request -> ");
        print_verbosity(*args, 0, "%s ? ", dst_ip);
        print_verbosity(*args, 0, "tell %s", src_ip);

        print_verbosity(*args, 1, "\nRequest -> ");
        print_verbosity(*args, 1, "%s ? ", dst_ip);
        print_verbosity(*args, 1, "tell %s", src_ip);
    } else {
        print_verbosity(*args, 0, "Reply -> ");
        print_verbosity(*args, 0, "%s ? ", src_mac);
        print_verbosity(*args, 0, "tell %s", src_ip);

        print_verbosity(*args, 1, "\nReply -> ");
        print_verbosity(*args, 1, "%s ? ", src_mac);
        print_verbosity(*args, 1, "tell %s", src_ip);
    }
    print_verbosity(*args, 1, "\n");
}