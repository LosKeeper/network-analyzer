#include "io.h"

void print_usage(const char *progname) {
    printf("Usage: %s [options]", progname);
    printf("Options:\n"
           "-i, --interface <interface>    Listen on <interface> for packets.\n"
           "-o, --origin                   Read from <file>.\n"
           "-f, --filter <filter>          Set BPF filter to <filter>.\n"
           "-v, --verbose <1,2,3>          Print verbose output.\n"
           "-h, --help                     Print this help menu.\n");
}

void parse_args(int argc, char **argv, args_s *argument) {
    int opt;
    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch (opt) {
        case 'i':
            argument->interface = optarg;
            break;
        case 'o':
            argument->file = optarg;
            break;
        case 'f':
            argument->filter = optarg;
            break;
        case 'v':
            argument->verbose = atoi(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        default:
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    validity_check(argument);
}

void validity_check(args_s *argument) {
    if (argument->interface == NULL) {
        fprintf(stderr, "You must specify an interface");
        print_usage("sniffer");
        exit(EXIT_FAILURE);
    }
}