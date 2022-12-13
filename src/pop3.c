#include "pop3.h"

int get_pop3(u_char *args, const u_char *packet) {
    (void)packet;
    print_verbosity(*args, 0, "POP3\t\t\t\t");
    return 1;
}