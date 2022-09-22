#include "decode.h"
#include "io.h"
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

    // Get arguments
    args_s argument = {0};
    parse_args(argc, argv, &argument);

    // Decode
    decode(argument.interface);

    return 0;
}