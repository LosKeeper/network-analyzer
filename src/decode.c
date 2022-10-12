#include "decode.h"
#include "bootp.h"
#include "dns.h"
#include "macro.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    (void)args;
    (void)header;
    struct ether_header *eth_header;
    printf("Trame reçue : \n");
    eth_header = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    printf("Adresse MAC source : %s ",
           ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    printf("Adresse MAC destination : %s, Type : %d \n",
           ether_ntoa((struct ether_addr *)eth_header->ether_dhost),
           htons(eth_header->ether_type));

    // On vérifie le type de packet
    switch (htons(eth_header->ether_type)) {
    case ETHERTYPE_IP:
        struct ip *ip;
        ip = (struct ip *)(packet);
        packet += sizeof(struct ip);
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
            packet += sizeof(struct tcphdr);
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
                printf(
                    "Type : %d, htype : %d, hlen : %d, hops : %d, "
                    "transaction id : %d, Delay : %d, Flags : %d, Adresse "
                    "IP client : %s, Your adresse IP  : %s, Adresse de Gateway "
                    ": %s, Adresse MAC source "
                    ": %s, Adresse MAC client : %s, Fichier de boot : %s, Nom "
                    "du serveur : %s\n",
                    bootp->op, bootp->htype, bootp->hlen, bootp->hops,
                    bootp->xid, bootp->secs, bootp->flags,
                    inet_ntoa(bootp->ciaddr), inet_ntoa(bootp->yiaddr),
                    inet_ntoa(bootp->siaddr), inet_ntoa(bootp->giaddr),
                    ether_ntoa((struct ether_addr *)bootp->chaddr), bootp->file,
                    bootp->sname);
                // Vendor specific informations
                struct vendorhdr *vendor;
                while (vendor->type != 0xff) {
                    printf("Vendor specific informations : \n");
                    vendor = (struct vendorhdr *)(packet);
                    packet += sizeof(struct vendorhdr);
                    char *data = malloc(vendor->len);
                    data = (char *)(packet);
                    packet += vendor->len;
                    // Get data of the vendor specific informations
                    // TODO : Get only dhcp options data
                    printf("Type : %d -> %s, Length : %d, Data : %s\n",
                           vendor->type, get_vendor_type(vendor->type),
                           vendor->len, data);
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
                        uint16_t len = 0;
                    }
                } else {
                    printf("Requête DNS\n");
                    // Requête DNS
                    // On recupere toutes les questions
                    for (int i = 0; i < dns->qdcount; i++) {
                        uint16_t len = 0;
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

    void decode(char *interface, char *file) {
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

            pcap_loop(handle, -1, got_packet, NULL);
        }
    }