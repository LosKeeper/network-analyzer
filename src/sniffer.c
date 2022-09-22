#include "decode.h"
#include "io.h"

int main(int argc, char *argv[]) {

    // Get arguments
    args_s argument = {0};
    parse_args(argc, argv, &argument);

    // Decode
    decode(argument.interface);

    return 0;
}