#include "decode.h"
#include "macro.h"

/**
 * @brief Global variable to count the number of packets
 */
int packet_count = 0;

/**
 * @brief Global variable corresponding to the port for FTP data
 */
int ftp_data = 25;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    (void)header;
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    packet_count++;

    // Verbose 1
    print_verbosity(*args, 1,
                    "--------------------------------------------------"
                    "--------------------------\n");
    print_verbosity(*args, 1, "\033[31m");
    print_verbosity(*args, 1, "Packet number : %d\n", packet_count);
    print_verbosity(*args, 1, "\033[32m");
    print_verbosity(*args, 1, "Ethernet : ");
    print_verbosity(*args, 1, "\033[0m");
    print_verbosity(*args, 1, "Source : %s, Destination : %s\n",
                    ether_ntoa((struct ether_addr *)eth_header->ether_shost),
                    ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // On vérifie le type de packet
    switch (htons(eth_header->ether_type)) {
    case ETHERTYPE_IP:
        struct ip *ip;
        ip = (struct ip *)(packet);
        packet += ip->ip_hl * 4;

        // Verbose 0
        print_verbosity(*args, 0, "%d\t\t\t\t", packet_count);
        print_verbosity(*args, 0, "%s\t\t\t\t", inet_ntoa(ip->ip_src));
        print_verbosity(*args, 0, "%s\t\t\t\t", inet_ntoa(ip->ip_dst));

        // Verbose 1
        print_verbosity(*args, 1, "\033[32m");
        print_verbosity(*args, 1, "IP : ");
        print_verbosity(*args, 1, "\033[0m");
        print_verbosity(*args, 1,
                        "Version : %d, Source : %s, Destination : "
                        "%s, Type de protocole : %d\n",
                        ip->ip_v, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst),
                        ip->ip_p);
        // On vérifie le type de protocole
        switch (ip->ip_p) {
        case IPPROTO_TCP:
            struct tcphdr *tcp;
            tcp = (struct tcphdr *)(packet);
            packet += tcp->th_off * 4;

            // Verbose 1
            print_verbosity(*args, 1, "\033[32m");
            print_verbosity(*args, 1, "TCP : ");
            print_verbosity(*args, 1, "\033[0m");
            print_verbosity(
                *args, 1,
                "Source : %d on port %d, Destination : %d on port %d\n",
                ntohs(ip->ip_src.s_addr), ntohs(tcp->th_sport),
                ntohs(ip->ip_dst.s_addr), ntohs(tcp->th_dport));

            // Get the lenght of the data in the packet
            int data_len =
                ntohs(ip->ip_len) - (ip->ip_hl * 4) - (tcp->th_off * 4);
            if (data_len <= 0) {
                print_verbosity(*args, 0, "TCP\t\t\t\t");
                get_tcp(args, tcp);
                goto tcp_end;
            }

            // On vérifie le port source
            switch (ntohs(tcp->th_sport)) {
            case SMTP_PORT:
                if (got_smtp(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case HTTP_PORT:
                if (got_http(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case TELNET_PORT:
                if (got_telnet(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case FTP_PORT:
                // printf("FTP_PORT");
                if ((ftp_data = got_ftp(args, packet, 0)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case DNS_PORT:
                if (got_dns(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3S_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;
            }

            // On gere le cas du port FTP data apart
            if (ntohs(tcp->th_dport) == ftp_data) {
                if (got_ftp_data(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;
            }

            // On vérifie le port destination si le port source n'est pas
            // reconu
            switch (ntohs(tcp->th_dport)) {
            case SMTP_PORT:
                if (got_smtp(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case HTTP_PORT:
                if (got_http(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case TELNET_PORT:
                if (got_telnet(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case FTP_PORT:
                if ((ftp_data = got_ftp(args, packet, 1)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case DNS_PORT:
                if (got_dns(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3S_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;
            }

            // On vérifie si c'est un FTP data
            if (ntohs(tcp->th_sport) == ftp_data) {
                if (got_ftp_data(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;
            }
        tcp_end:;
            break;
        case IPPROTO_UDP:
            struct udphdr *udp;
            udp = (struct udphdr *)(packet);
            packet += sizeof(struct udphdr);

            print_verbosity(*args, 1, "UDP ");
            print_verbosity(*args, 1, "From Port : %d , ",
                            ntohs(udp->uh_sport));
            print_verbosity(*args, 1, "To Port : %d\n", ntohs(udp->uh_dport));

            // On vérifie le port source
            switch (ntohs(udp->uh_sport)) {
            case DNS_PORT:
                got_dns(args, packet);
                goto udp_end;

            case BOOTP_PORT:
                got_bootp(args, packet);
                goto udp_end;
            }

            // On vérifie le port destination
            switch (ntohs(udp->uh_dport)) {
            case DNS_PORT:
                got_dns(args, packet);
                goto udp_end;

            case BOOTP_PORT:
                got_bootp(args, packet);
                goto udp_end;
            }
        }

    udp_end:;
        break;
    case ETHERTYPE_IPV6:
        print_verbosity(*args, 1, "IPv6 ");
        struct ip6_hdr *ip6;
        ip6 = (struct ip6_hdr *)(packet);
        packet += sizeof(struct ip6_hdr);
        char *src_ip6 = malloc(INET6_ADDRSTRLEN);
        char *dst_ip6 = malloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip6, INET6_ADDRSTRLEN);
        print_verbosity(*args, 0, "%d\t\t\t\t", packet_count);
        print_verbosity(*args, 0, "%s\t\t", src_ip6);
        print_verbosity(*args, 0, "%s\t\t", dst_ip6);

        switch (ip6->ip6_nxt) {
        case IPPROTO_TCP:
            struct tcphdr *tcp;
            tcp = (struct tcphdr *)(packet);
            packet += sizeof(struct tcphdr);

            print_verbosity(*args, 1, "TCP ");
            print_verbosity(*args, 1, "From Port : %d , ",
                            ntohs(tcp->th_sport));
            print_verbosity(*args, 1, "To Port : %d\n", ntohs(tcp->th_dport));

            // On vérifie le port source
            switch (ntohs(tcp->th_sport)) {
            case SMTP_PORT:
                if (got_smtp(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case HTTP_PORT:
                if (got_http(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case TELNET_PORT:
                if (got_telnet(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case FTP_PORT:
                if ((ftp_data = got_ftp(args, packet, 0)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3S_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;
            }

            // On gere le cas du port FTP data apart
            if (ntohs(tcp->th_dport) == ftp_data) {
                if (got_ftp_data(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;
            }

            // On vérifie le port destination si le port source n'est pas
            // reconu
            switch (ntohs(tcp->th_dport)) {
            case SMTP_PORT:
                if (got_smtp(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case HTTP_PORT:
                if (got_http(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case TELNET_PORT:
                if (got_telnet(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case FTP_PORT:
                if ((ftp_data = got_ftp(args, packet, 1)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3S_PORT:
                if (get_pop3(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;
            }

            // On gere le cas du port FTP data a part
            if (ntohs(tcp->th_sport) == ftp_data) {
                if (got_ftp_data(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;
            }

        tcp6_end:;
            break;

        case IPPROTO_UDP:
            struct udphdr *udp;
            udp = (struct udphdr *)(packet);
            packet += sizeof(struct udphdr);

            print_verbosity(*args, 1, "UDP ");
            print_verbosity(*args, 1, "From Port : %d , ",
                            ntohs(udp->uh_sport));
            print_verbosity(*args, 1, "To Port : %d\n", ntohs(udp->uh_dport));

            // On vérifie le port source
            switch (ntohs(udp->uh_sport)) {
            case DNS_PORT:
                got_dns(args, packet);
                goto udp6_end;

            case BOOTP_PORT:
                got_bootp(args, packet);
                goto udp6_end;
            }

            // On vérifie le port destination
            switch (ntohs(udp->uh_dport)) {
            case DNS_PORT:
                got_dns(args, packet);
                goto udp6_end;

            case BOOTP_PORT:
                got_bootp(args, packet);
                goto udp6_end;
            }
        }
    udp6_end:;
        break;

    case ETHERTYPE_ARP:
        print_verbosity(*args, 0, "%d\t\t\t\t", packet_count);
        get_arp(args, packet);
        break;
    }
    printf("\n");
}

void decode(char *interface, char *file, u_char verbosity) {
    if (interface) {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];

        if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) ==
            NULL) {
            panic("pcap_open_live");
        }

        pcap_loop(handle, -1, got_packet, &verbosity);

        pcap_close(handle);
    } else {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];

        if ((handle = pcap_open_offline(file, errbuf)) == NULL) {
            panic("pcap_open_offline");
        }

        // Print header in terminal for verbosity level 0
        if (verbosity == 0) {
            // Print header in terminal in red
            print_verbosity(verbosity, 0, "\033[0;31m");
            print_verbosity(verbosity, 0, "Packet number\t\t\t");
            print_verbosity(verbosity, 0, "Source\t\t\t\t\t");
            print_verbosity(verbosity, 0, "Destination\t\t\t\t");
            print_verbosity(verbosity, 0, "Protocol\t\t\t");
            print_verbosity(verbosity, 0, "Infos\n");
            print_verbosity(verbosity, 0, "\033[0m");
        }

        pcap_loop(handle, -1, got_packet, &verbosity);

        pcap_close(handle);
    }
}