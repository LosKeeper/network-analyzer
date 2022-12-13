#include "imap.h"

int get_imap(u_char *args, const u_char *packet) {
    (void)packet;
    print_verbosity(*args, 0, "IMAP\t\t\t\t");
    return 1;
}