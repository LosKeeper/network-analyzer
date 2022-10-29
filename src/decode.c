#include "decode.h"
#include "bootp.h"
#include "dns.h"
#include "macro.h"
#include "verbose.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    (void)header;
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    print_verbosity(*args, 2, "Adresse MAC source : %s ",
                    ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    print_verbosity(*args, 2, "Adresse MAC destination : %s, Type : %d \n",
                    ether_ntoa((struct ether_addr *)eth_header->ether_dhost),
                    htons(eth_header->ether_type));

    // On vérifie le type de packet
    switch (htons(eth_header->ether_type)) {
    case ETHERTYPE_IP:
        struct ip *ip;
        ip = (struct ip *)(packet);
        packet += ip->ip_hl * 4;
        printf(
            "Version IP : %d, Taille de l'entête IP : %d, Type de service : "
            "%d, "
            "Taille totale : %d, Identifiant : %d, Offset : %d, TTL : %d, "
            "Protocole : %d, Somme de contrôle : %d, Adresse IP source : %s, "
            "Adresse IP destination : %s\n",
            ip->ip_v, ip->ip_hl, ip->ip_tos, ip->ip_len, ip->ip_id, ip->ip_off,
            ip->ip_ttl, ip->ip_p, ip->ip_sum, inet_ntoa(ip->ip_src),
            inet_ntoa(ip->ip_dst));
        // On vérifie le type de protocole
        switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("Protocole TCP\n");
            struct tcphdr *tcp;
            tcp = (struct tcphdr *)(packet);
            packet += tcp->th_off * 4;
            printf(
                "Port source : %d, Port destination : %d, Numéro de séquence "
                ": %d, Numéro d'acquittement : %d, Taille de l'entête TCP : "
                "%d, Flags : %d, Taille de la fenêtre : %d, Somme de "
                "contrôle : %d, Pointeur d'urgence : %d\n",
                ntohs(tcp->th_sport), ntohs(tcp->th_dport), tcp->th_seq,
                tcp->th_ack, tcp->th_off, tcp->th_flags, tcp->th_win,
                tcp->th_sum, tcp->th_urp);
            break;
        case IPPROTO_UDP:
            printf("Protocole UDP\n");
            struct udphdr *udp;
            udp = (struct udphdr *)(packet);
            packet += sizeof(struct udphdr);
            printf("Port source : %d, Port destination : %d, Taille : %d\n",
                   ntohs(udp->uh_sport), ntohs(udp->uh_dport), udp->uh_ulen);
            // On vérifie si c'est un BOOTP
            if (ntohs(udp->uh_sport) == 67 || ntohs(udp->uh_dport) == 67) {
                printf("BOOTP\n");
                struct bootphdr *bootp;
                bootp = (struct bootphdr *)(packet);
                packet += sizeof(struct bootphdr);
                print_bootp(bootp);
                // Vendor specific informations
                struct vendorhdr *vendor;
                vendor = (struct vendorhdr *)(packet);
                while (vendor->type != 0xff) {
                    printf("Vendor specific informations : \n");
                    vendor = (struct vendorhdr *)(packet);
                    packet += sizeof(struct vendorhdr);

                    // Trim the data to print only the useful informations
                    char *trimmed_data = malloc(vendor->len);
                    int i = 0;
                    while (i < vendor->len) {
                        if (isprint(packet[i])) {
                            trimmed_data[i] = packet[i];
                        } else {
                            trimmed_data[i] = ' ';
                        }
                        i++;
                    }

                    packet += vendor->len;
                    // Get data of the vendor specific informations
                    // TODO : Get only dhcp options data
                    printf("Type : %d -> %s, Length : %d, Data : %s\n",
                           vendor->type, get_vendor_type(vendor->type),
                           vendor->len, trimmed_data);
                }
            }
            // On vérifie si c'est un DNS
            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53) {
                printf("DNS\n");
                struct dnshdr *dns;
                dns = (struct dnshdr *)(packet);
                packet += sizeof(struct dnshdr);
                printf("ID : %d, Flags : %d, Questions : %d, Réponses : %d, "
                       "Autorités : %d, Supplémentaires : %d\n",
                       dns->id, dns->flags, dns->qdcount, dns->ancount,
                       dns->nscount, dns->arcount);

                // On vérifie si c'est une requête ou une réponse
                if (dns->flags & 0x8000) {
                    printf("Réponse DNS\n");
                    // Réponse DNS
                    // On recupere toutes les reponses
                    for (int i = 0; i < dns->qdcount; i++) {
                        printf("Question : ");
                        uint8_t len;
                        while ((len = *(uint8_t *)packet) != 0) {
                            packet += sizeof(len);
                            char *data = malloc(len);
                            data = (char *)(packet);
                            packet += len;
                            printf("%s.", data);
                        }
                        // printf("\n");
                        // struct dnsanswer *dnsans;
                        // dnsans = (struct dnsanswer *)(packet);
                        // packet += sizeof(struct dnsanswer);
                        // printf("Type : %d, Class : %d, TTL : %d, Data
                        // length : "
                        //        "%d, IP : %s\n",
                        //        dnsans->type, dnsans->class, dnsans->ttl,
                        //        dnsans->rdlength,
                        //        inet_ntoa(dnsans->rdata));
                    }

                } else {
                    printf("Requête DNS\n");
                    // Requête DNS
                    // On recupere toutes les questions
                    for (int i = 0; i < dns->qdcount; i++) {
                        printf("Réponse : ");
                        uint8_t len;
                        while ((len = *(uint8_t *)packet) != 0) {
                            packet += sizeof(len);
                            char *data = malloc(len);
                            data = (char *)(packet);
                            packet += len;
                            printf("%s.", data);
                        }
                        // printf("\n");
                        // struct dnsquestion *dnsq;
                        // dnsq = (struct dnsquestion *)(packet);
                        // packet += sizeof(struct dnsquestion);
                        // printf("Type : %d, Class : %d\n", dnsq->qtype,
                        //        dnsq->qclass);
                    }
                }
            }
            break;
        }
        break;
    case ETHERTYPE_ARP:
        printf("ARP\n");
        break;
    case ETHERTYPE_REVARP:
        printf("REVARP\n");
        break;
    }
    printf("\n");
}

void decode(char *interface, char *file, u_char verbosity) {
    if (interface) {
        pcap_t *handle;
        // struct bpf_program *fp;
        char errbuf[PCAP_ERRBUF_SIZE];
        // bpf_u_int32 netmask;

        if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) ==
            NULL) {
            panic("pcap_open_live");
        }

        pcap_loop(handle, -1, got_packet, NULL);
    } else {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];

        if ((handle = pcap_open_offline(file, errbuf)) == NULL) {
            panic("pcap_open_offline");
        }

        pcap_loop(handle, -1, got_packet, &verbosity);
    }
}