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