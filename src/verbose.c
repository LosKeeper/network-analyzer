#include "verbose.h"

void print_verbosity(u_char desired_level, u_char msg_level, const char *msg,
                     ...) {
    if (desired_level >= msg_level) {
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
    }
}