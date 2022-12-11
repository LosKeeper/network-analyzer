#include "http.h"

int got_http(u_char *args, const u_char *packet) {
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
    print_verbosity(*args, 1, "Protocole HTTP\n");
    // Print only printable characters
    for (size_t i = 0; i < strlen((char *)packet); i++) {
        if (isprint(packet[i])) {
            print_verbosity(*args, 2, "%c", packet[i]);
        }
    }
}