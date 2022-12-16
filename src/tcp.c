#include "tcp.h"

void get_tcp(u_char *args, struct tcphdr *tcp) {
    // Si aucun port n'est reconnu, on affiche le contenu du paquet
    // TCP
    if (tcp->th_flags & TH_SYN) {
        print_verbosity(*args, 0, "SYN,");
    }
    if (tcp->th_flags & TH_ACK) {
        print_verbosity(*args, 0, "ACK,");
    }
    if (tcp->th_flags & TH_FIN) {
        print_verbosity(*args, 0, "FIN,");
    }
    if (tcp->th_flags & TH_RST) {
        print_verbosity(*args, 0, "RST,");
    }
    if (tcp->th_flags & TH_PUSH) {
        print_verbosity(*args, 0, "PUSH,");
    }
    if (tcp->th_flags & TH_URG) {
        print_verbosity(*args, 0, "URG,");
    }
}

char *get_flags(struct tcphdr *tcp) {
    char *flags = malloc(6 * sizeof(char));
    int i = 0;
    if (tcp->th_flags & TH_SYN) {
        flags[i] = 'S';
        i++;
    }
    if (tcp->th_flags & TH_ACK) {
        flags[i] = 'A';
        i++;
    }
    if (tcp->th_flags & TH_FIN) {
        flags[i] = 'F';
        i++;
    }
    if (tcp->th_flags & TH_RST) {
        flags[i] = 'R';
        i++;
    }
    if (tcp->th_flags & TH_PUSH) {
        flags[i] = 'P';
        i++;
    }
    if (tcp->th_flags & TH_URG) {
        flags[i] = 'U';
        i++;
    }
    flags[i] = '\0';
    return flags;
}