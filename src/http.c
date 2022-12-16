#include "http.h"

int got_http(u_char *args, const u_char *packet) {
    switch (*args) {
    case 0:
        // Verbose 0
        print_verbosity(*args, 0, "HTTP\t\t\t\t");
        // Print the type of the resquest
        if (strncmp((char *)packet, "GET", 3) == 0) {
            print_verbosity(*args, 0, "GET ");
            int i = 4;
            while (isprint(packet[i])) {
                print_verbosity(*args, 0, "%c", packet[i]);
                i++;
            }
            return 1;
        } else if (strncmp((char *)packet, "POST", 4) == 0) {
            print_verbosity(*args, 0, "POST");
            return 1;
        } else if (strncmp((char *)packet, "HEAD", 4) == 0) {
            print_verbosity(*args, 0, "HEAD");
            return 1;
        } else if (strncmp((char *)packet, "PUT", 3) == 0) {
            print_verbosity(*args, 0, "PUT");
            return 1;
        } else if (strncmp((char *)packet, "DELETE", 6) == 0) {
            print_verbosity(*args, 0, "DELETE");
            return 1;
        } else if (strncmp((char *)packet, "CONNECT", 7) == 0) {
            print_verbosity(*args, 0, "CONNECT");
            return 1;
        } else if (strncmp((char *)packet, "OPTIONS", 7) == 0) {
            print_verbosity(*args, 0, "OPTIONS");
            return 1;
        } else if (strncmp((char *)packet, "TRACE", 5) == 0) {
            print_verbosity(*args, 0, "TRACE");
            return 1;
        } else if (strncmp((char *)packet, "PATCH", 5) == 0) {
            print_verbosity(*args, 0, "PATCH");
            return 1;
        }
        return 0;

    default:
        // Verbose 1
        char *buff = malloc(256);
        int i = 0;
        while (isprint(packet[i])) {
            buff[i] = packet[i];
            i++;
        }
        buff[i] = '\0';
        // if the packet is empty dont print it
        if (strlen(buff) > 3) {
            print_verbosity(*args, 1, "\033[32m");
            print_verbosity(*args, 1, "HTTP : ");
            print_verbosity(*args, 1, "\033[0m");
            print_verbosity(*args, 1, "%s\n", buff);

            print_verbosity(*args, 2, "\033[32m");
            print_verbosity(*args, 2, "HTTP : ");
            print_verbosity(*args, 2, "\033[0m");
            print_verbosity(*args, 2, "%s\n", buff);
        }
        free(buff);
        return 1;
    }
    return 0;
}

int got_https(u_char *args, const u_char *packet) {
    (void)packet;
    switch (*args) {
    case 0:
        print_verbosity(*args, 0, "HTTPS\t\t\t\t");
        print_verbosity(*args, 0, "Encrypted packet");
        return 1;

    case 1:
        print_verbosity(*args, 1, "\033[32m");
        print_verbosity(*args, 1, "HTTPS : ");
        print_verbosity(*args, 1, "\033[0m");
        print_verbosity(*args, 1, "Encrypted packet\n");
        return 1;

    case 2:
        print_verbosity(*args, 2, "\033[32m");
        print_verbosity(*args, 2, "HTTPS : ");
        print_verbosity(*args, 2, "\033[0m");
        print_verbosity(*args, 2, "Encrypted packet\n");
        return 1;
    }
    return 0;
}