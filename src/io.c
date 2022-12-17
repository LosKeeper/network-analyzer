#include "io.h"

void print_usage(const char *progname) {
    printf("Usage: %s [options]", progname);
    printf(
        "Options:\n"
        "-i <interface>    Listen on <interface> for packets.\n"
        "-o                Read from <file>.\n"
        "-f <filter>       Set BPF filter to <filter>. NOT IMPLEMENTED YET !\n"
        "-v <1,2,3>        Print verbose output.\n"
        "-h                Print this help menu.\n");
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
    if (argument->interface == NULL && argument->file == NULL) {
        fprintf(stderr, "You must specify an interface or a file");
        print_usage("sniffer");
        exit(EXIT_FAILURE);
    }
    if (argument->interface != NULL && argument->file != NULL) {
        fprintf(stderr, "You must specify an interface or a file, not both");
        print_usage("sniffer");
        exit(EXIT_FAILURE);
    }
}