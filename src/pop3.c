#include "pop3.h"

int get_pop3(u_char *args, const u_char *packet, int data_len) {
    switch (*args) {
    case 0:
        print_verbosity(*args, 0, "POP3\t\t\t\t");
        return 1;

    case 1:
        print_verbosity(*args, 1, "\033[32m");
        print_verbosity(*args, 1, "POP3 : ");
        print_verbosity(*args, 1, "\033[0m");

        // Print the rest of the packet
        int i = 0;
        while (isprint(packet[i]) && i < data_len) {
            print_verbosity(*args, 1, "%c", packet[i]);
            i++;
        }
        print_verbosity(*args, 1, "\n");
        return 1;

    case 2:
        print_verbosity(*args, 2, "\033[32m");
        print_verbosity(*args, 2, "POP3 : ");
        print_verbosity(*args, 2, "\033[0m");

        // Print the rest of the packet
        i = 0;
        while (isprint(packet[i]) && i < data_len) {
            print_verbosity(*args, 2, "%c", packet[i]);
            i++;
        }
        print_verbosity(*args, 2, "\n");
        return 1;
    }
    return 0;
}