#include "decode.h"
#include "macro.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    (void)args;

    struct ether_header *eth_header;
    printf("Trame reçue : \n");
    eth_header = (struct ether_header *)packet;
    printf("Adresse MAC source : %s ",
           ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    printf("Adresse MAC destination : %s, Type : %d \n",
           ether_ntoa((struct ether_addr *)eth_header->ether_dhost),
           htons(eth_header->ether_type));

    // On vérifie le type de packet
    switch (htons(eth_header->ether_type)) {
    case ETHERTYPE_IP:
        struct ip *ip;
        ip = (struct ip *)(packet + sizeof(struct ether_header));
        printf(
            "Version IP : %d, Taille de l'entête IP : %d, Type de service : "
            "%d, "
            "Taille totale : %d, Identifiant : %d, Offset : %d, TTL : %d, "
            "Protocole : %d, Somme de contrôle : %d, Adresse IP source : %s, "
            "Adresse IP destination : %s\n",
            ip->ip_v, ip->ip_hl, ip->ip_tos, ip->ip_len, ip->ip_id, ip->ip_off,
            ip->ip_ttl, ip->ip_p, ip->ip_sum, inet_ntoa(ip->ip_src),
            inet_ntoa(ip->ip_dst));
        break;
    case ETHERTYPE_ARP:
        printf("ARP\n");
        break;
    case ETHERTYPE_REVARP:
        printf("REVARP\n");
        break;
    }

    for (bpf_u_int32 i = 0; i < header->caplen; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");
}

void decode(char *interface) {
    pcap_t *handle;
    // struct bpf_program *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    // bpf_u_int32 netmask;

    if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        panic("pcap_open_live");
    }

    pcap_loop(handle, -1, got_packet, NULL);
}