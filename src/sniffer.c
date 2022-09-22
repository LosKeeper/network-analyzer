#include "decode.h"
#include "io.h"

int main(int argc, char *argv[]) {

    // Get arguments
    args_s argument = {0};
    parse_args(argc, argv, &argument);

    // Decode
    if (argument.interface != NULL) {
        decode(argument.interface, NULL);
    } else {
        decode(NULL, argument.file);
    }

    return 0;
}