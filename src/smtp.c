#include "smtp.h"

int got_smtp(u_char *args, const u_char *packet, int data_len) {
    switch (*args) {
    case 0:
        print_verbosity(*args, 0, "SMTP\t\t\t\t");
        if (strncmp((char *)packet, "HELO", 4) == 0) {
            print_verbosity(*args, 0, "HELO");
            return 1;
        } else if (strncmp((char *)packet, "EHLO", 4) == 0) {
            print_verbosity(*args, 0, "EHLO");
            return 1;
        } else if (strncmp((char *)packet, "MAIL FROM", 9) == 0) {
            print_verbosity(*args, 0, "MAIL FROM");
            // Print the sender
            for (size_t i = 10; i < strlen((char *)packet) && packet[i] != '>';
                 i++) {
                if (isprint(packet[i]) && packet[i] != '<') {
                    print_verbosity(*args, 0, "%c", packet[i]);
                }
            }
            return 1;
        } else if (strncmp((char *)packet, "RCPT TO", 7) == 0) {
            print_verbosity(*args, 0, "RCPT TO ");
            // Print the recipient
            for (size_t i = 10; i < strlen((char *)packet) && packet[i] != '>';
                 i++) {
                if (isprint(packet[i]) && packet[i] != '<') {
                    print_verbosity(*args, 0, "%c", packet[i]);
                }
            }
            return 1;
        } else if (strncmp((char *)packet, "DATA", 4) == 0) {
            print_verbosity(*args, 0, "DATA");
            return 1;
        } else if (strncmp((char *)packet, "RSET", 4) == 0) {
            print_verbosity(*args, 0, "RSET");
            return 1;
        } else if (strncmp((char *)packet, "VRFY", 4) == 0) {
            print_verbosity(*args, 0, "VRFY");
            return 1;
        } else if (strncmp((char *)packet, "EXPN", 4) == 0) {
            print_verbosity(*args, 0, "EXPN");
            return 1;
        } else if (strncmp((char *)packet, "HELP", 4) == 0) {
            print_verbosity(*args, 0, "HELP");
            return 1;
        } else if (strncmp((char *)packet, "NOOP", 4) == 0) {
            print_verbosity(*args, 0, "NOOP");
            return 1;
        } else if (strncmp((char *)packet, "QUIT", 4) == 0) {
            print_verbosity(*args, 0, "QUIT");
            return 1;
        } else if (strncmp((char *)packet, "TURN", 4) == 0) {
            print_verbosity(*args, 0, "TURN");
            return 1;
        } else if (strncmp((char *)packet, "AUTH", 4) == 0) {
            print_verbosity(*args, 0, "AUTH");
            return 1;
        } else if (strncmp((char *)packet, "STARTTLS", 8) == 0) {
            print_verbosity(*args, 0, "STARTTLS");
            return 1;
        }
        return 0;

    case 1:
        print_verbosity(*args, 1, "\033[32m");
        print_verbosity(*args, 1, "SMTP : ");
        print_verbosity(*args, 1, "\033[0m");

        // Print the rest of the packet
        int i = 0;
        while (isprint(packet[i]) && i < data_len) {
            print_verbosity(*args, 1, "%c", packet[i]);
            i++;
        }
        print_verbosity(*args, 1, "\n");
        return 1;
    }
    return 0;
}