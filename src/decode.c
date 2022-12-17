#include "decode.h"
#include "macro.h"

/**
 * @brief Global variable to count the number of packets
 */
unsigned int packet_count = 0;

/**
 * @brief Global variable corresponding to the port for FTP data if it changes
 */
unsigned int ftp_data = 20;

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
    print_verbosity(*args, 1, "Packet number : %u\n", packet_count);
    print_verbosity(*args, 1, "\033[32m");
    print_verbosity(*args, 1, "Ethernet : ");
    print_verbosity(*args, 1, "\033[0m");
    print_verbosity(*args, 1, "Source : %s, Destination : %s\n",
                    ether_ntoa((struct ether_addr *)eth_header->ether_shost),
                    ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // Verbose 2
    print_verbosity(*args, 2,
                    "--------------------------------------------------"
                    "--------------------------\n");
    print_verbosity(*args, 2, "\033[34m");
    print_verbosity(*args, 2, "Packet number : %u\n", packet_count);
    print_verbosity(*args, 2, "\033[32m");
    print_verbosity(*args, 2, "Ethernet : ");
    print_verbosity(*args, 2, "\033[0m");
    print_verbosity(*args, 2, "Source : %s, Destination : %s, Type : %u\n",
                    ether_ntoa((struct ether_addr *)eth_header->ether_shost),
                    ether_ntoa((struct ether_addr *)eth_header->ether_dhost),
                    eth_header->ether_type);

    // On vérifie le type de packet
    switch (htons(eth_header->ether_type)) {
    case ETHERTYPE_IP:
        struct ip *ip;
        ip = (struct ip *)(packet);
        packet += ip->ip_hl * 4;

        // Verbose 0
        print_verbosity(*args, 0, "%u\t\t\t\t", packet_count);
        print_verbosity(*args, 0, "%s\t\t\t\t", inet_ntoa(ip->ip_src));
        print_verbosity(*args, 0, "%s\t\t\t\t", inet_ntoa(ip->ip_dst));

        // Verbose 1
        print_verbosity(*args, 1, "\033[32m");
        print_verbosity(*args, 1, "IP : ");
        print_verbosity(*args, 1, "\033[0m");
        print_verbosity(*args, 1, "Version : %u, ", ip->ip_v);
        print_verbosity(*args, 1, "Source : %s, ", inet_ntoa(ip->ip_src));
        print_verbosity(*args, 1, "Destination : %s\n", inet_ntoa(ip->ip_dst));

        // Verbose 2
        print_verbosity(*args, 2, "\033[32m");
        print_verbosity(*args, 2, "IP : ");
        print_verbosity(*args, 2, "\033[0m");
        print_verbosity(*args, 2, "Version : %u, ", ip->ip_v);
        print_verbosity(*args, 2, "Header length : %u, ", ip->ip_hl);
        print_verbosity(*args, 2, "Type of service : %u, ", ip->ip_tos);
        print_verbosity(*args, 2, "Total length : %u, ", ntohs(ip->ip_len));
        print_verbosity(*args, 2, "Identification : %u, ", ntohs(ip->ip_id));
        print_verbosity(*args, 2, "Fragment offset : %u, ", ntohs(ip->ip_off));
        print_verbosity(*args, 2, "Time to live : %u, ", ip->ip_ttl);
        print_verbosity(*args, 2, "Protocol : %u, ", ip->ip_p);
        print_verbosity(*args, 2, "Checksum : %u, ", ntohs(ip->ip_sum));
        print_verbosity(*args, 2, "Source : %s, ", inet_ntoa(ip->ip_src));
        print_verbosity(*args, 2, "Destination : %s\n", inet_ntoa(ip->ip_dst));

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
            print_verbosity(*args, 1, "From port : %u to port : %u\n",
                            ntohs(tcp->th_sport), ntohs(tcp->th_dport));

            // Verbose 2
            print_verbosity(*args, 2, "\033[32m");
            print_verbosity(*args, 2, "TCP : ");
            print_verbosity(*args, 2, "\033[0m");
            print_verbosity(*args, 2, "From port : %u, ", ntohs(tcp->th_sport));
            print_verbosity(*args, 2, "to port %u, ", ntohs(tcp->th_dport));
            print_verbosity(*args, 2, "Sequence number : %u, ",
                            ntohl(tcp->th_seq));
            print_verbosity(*args, 2, "Acknowledgement number : %u, ",
                            ntohl(tcp->th_ack));
            print_verbosity(*args, 2, "Data offset : %u, ", tcp->th_off);
            print_verbosity(*args, 2, "Flags : %s, ", get_flags(tcp));
            print_verbosity(*args, 2, "Window : %u, ", ntohs(tcp->th_win));
            print_verbosity(*args, 2, "Checksum : %u, ", ntohs(tcp->th_sum));
            print_verbosity(*args, 2, "Urgent pointer : %u\n",
                            ntohs(tcp->th_urp));

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
                if (got_smtp(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case HTTP_PORT:
                if (got_http(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case HTTPS_PORT:
                if (got_https(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case TELNET_PORT:
                if (got_telnet(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case FTP_PORT:
                if ((ftp_data = got_ftp(args, packet, 0, data_len)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case DNS_PORT:
                if (got_dns(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3S_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_PORT:
                if (get_imap(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet, data_len) == 0) {
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
                if (got_smtp(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case HTTP_PORT:
                if (got_http(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case HTTPS_PORT:
                if (got_https(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case TELNET_PORT:
                if (got_telnet(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case FTP_PORT:
                if ((ftp_data = got_ftp(args, packet, 1, data_len)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case DNS_PORT:
                if (got_dns(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case POP3S_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_PORT:
                if (get_imap(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet, data_len) == 0) {
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

            // Verbose 1
            print_verbosity(*args, 1, "\033[32m");
            print_verbosity(*args, 1, "UDP : ");
            print_verbosity(*args, 1, "\033[0m");
            print_verbosity(*args, 1,
                            "Source port : %u, Destination port : %u\n",
                            ntohs(udp->uh_sport), ntohs(udp->uh_dport));

            // Verbose 2
            print_verbosity(*args, 2, "\033[32m");
            print_verbosity(*args, 2, "UDP : ");
            print_verbosity(*args, 2, "\033[0m");
            print_verbosity(*args, 2, "Source port : %u, ",
                            ntohs(udp->uh_sport));
            print_verbosity(*args, 2, "Destination port : %u, ",
                            ntohs(udp->uh_dport));
            print_verbosity(*args, 2, "Length : %u, ", ntohs(udp->uh_ulen));
            print_verbosity(*args, 2, "Checksum : %u\n", ntohs(udp->uh_sum));

            int data_len_udp = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

            // On vérifie le port source
            switch (ntohs(udp->uh_sport)) {
            case DNS_PORT:
                got_dns(args, packet, data_len_udp);
                goto udp_end;

            case BOOTP_PORT_CLIENT:
                got_bootp(args, packet);
                goto udp_end;

            case BOOTP_PORT_SERVER:
                got_bootp(args, packet);
                goto udp_end;
            }

            // On vérifie le port destination
            switch (ntohs(udp->uh_dport)) {
            case DNS_PORT:
                got_dns(args, packet, data_len_udp);
                goto udp_end;

            case BOOTP_PORT_CLIENT:
                got_bootp(args, packet);
                goto udp_end;

            case BOOTP_PORT_SERVER:
                got_bootp(args, packet);
                goto udp_end;
            }
        udp_end:;
            break;
        }

        break;
    case ETHERTYPE_IPV6:
        struct ip6_hdr *ip6;
        ip6 = (struct ip6_hdr *)(packet);
        packet += sizeof(struct ip6_hdr);
        char *src_ip6 = malloc(INET6_ADDRSTRLEN);
        char *dst_ip6 = malloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip6, INET6_ADDRSTRLEN);
        print_verbosity(*args, 0, "%u\t\t\t\t", packet_count);
        print_verbosity(*args, 0, "%s\t\t", src_ip6);
        print_verbosity(*args, 0, "%s\t\t", dst_ip6);

        // Verbose 1
        print_verbosity(*args, 1, "\033[32m");
        print_verbosity(*args, 1, "IPv6 : ");
        print_verbosity(*args, 1, "\033[0m");
        print_verbosity(*args, 1, "Source IP : %s, ", src_ip6);
        print_verbosity(*args, 1, "Destination IP : %s\n", dst_ip6);

        // Verbose 2
        print_verbosity(*args, 2, "\033[32m");
        print_verbosity(*args, 2, "IPv6 : ");
        print_verbosity(*args, 2, "\033[0m");
        print_verbosity(*args, 2, "Version : %u, ", ip6->ip6_vfc >> 4);
        print_verbosity(*args, 2, "Traffic class : %u, ",
                        (ip6->ip6_vfc & 0x0f) << 4 | ip6->ip6_flow >> 28);
        print_verbosity(*args, 2, "Flow label : %u, ",
                        ip6->ip6_flow & 0x0fffffff);
        print_verbosity(*args, 2, "Payload length : %u, ",
                        ntohs(ip6->ip6_plen));
        print_verbosity(*args, 2, "Next header : %u, ", ip6->ip6_nxt);
        print_verbosity(*args, 2, "Hop limit : %u, ", ip6->ip6_hops);
        print_verbosity(*args, 2, "Source IP : %s, ", src_ip6);
        print_verbosity(*args, 2, "Destination IP : %s\n", dst_ip6);

        switch (ip6->ip6_nxt) {
        case IPPROTO_TCP:
            struct tcphdr *tcp;
            tcp = (struct tcphdr *)(packet);
            packet += sizeof(struct tcphdr);

            // Verbose 1
            print_verbosity(*args, 1, "\033[32m");
            print_verbosity(*args, 1, "TCP : ");
            print_verbosity(*args, 1, "\033[0m");
            print_verbosity(*args, 1, "From Port : %u , ",
                            ntohs(tcp->th_sport));
            print_verbosity(*args, 1, "To Port : %u\n", ntohs(tcp->th_dport));

            // Verbose 2
            print_verbosity(*args, 2, "\033[32m");
            print_verbosity(*args, 2, "TCP : ");
            print_verbosity(*args, 2, "\033[0m");
            print_verbosity(*args, 2, "Source port : %u, ",
                            ntohs(tcp->th_sport));
            print_verbosity(*args, 2, "Destination port : %u, ",

                            ntohs(tcp->th_dport));
            print_verbosity(*args, 2, "Sequence number : %u, ",
                            ntohl(tcp->th_seq));
            print_verbosity(*args, 2, "Acknowledgment number : %u, ",
                            ntohl(tcp->th_ack));
            print_verbosity(*args, 2, "Data offset : %u, ", tcp->th_off >> 4);
            print_verbosity(*args, 2, "Reserved : %u, ",
                            (tcp->th_off & 0x0f) >> 1);
            print_verbosity(*args, 2, "Flags : %s, ", get_flags(tcp));
            print_verbosity(*args, 2, "Window size : %u, ", ntohs(tcp->th_win));
            print_verbosity(*args, 2, "Checksum : %u, ", ntohs(tcp->th_sum));
            print_verbosity(*args, 2, "Urgent pointer : %u\n",
                            ntohs(tcp->th_urp));

            int data_len = ntohs(ip6->ip6_plen) - sizeof(struct tcphdr);
            if (data_len <= 0) {
                print_verbosity(*args, 0, "TCP\t\t\t\t");
                get_tcp(args, tcp);
                goto tcp6_end;
            }

            // On vérifie le port source
            switch (ntohs(tcp->th_sport)) {
            case SMTP_PORT:
                if (got_smtp(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case HTTP_PORT:
                if (got_http(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case HTTPS_PORT:
                if (got_https(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case TELNET_PORT:
                if (got_telnet(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case FTP_PORT:
                if ((ftp_data = got_ftp(args, packet, 0, data_len)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3S_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_PORT:
                if (get_imap(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet, data_len) == 0) {
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
                if (got_smtp(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case HTTP_PORT:
                if (got_http(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case HTTPS_PORT:
                if (got_https(args, packet) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case TELNET_PORT:
                if (got_telnet(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case FTP_PORT:
                if ((ftp_data = got_ftp(args, packet, 1, data_len)) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case POP3S_PORT:
                if (get_pop3(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_PORT:
                if (get_imap(args, packet, data_len) == 0) {
                    get_tcp(args, tcp);
                }
                goto tcp6_end;

            case IMAP_SSL_PORT:
                if (get_imap(args, packet, data_len) == 0) {
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

            // Verbose 1
            print_verbosity(*args, 1, "\033[32m");
            print_verbosity(*args, 1, "UDP : ");
            print_verbosity(*args, 1, "\033[0m");
            print_verbosity(*args, 1,
                            "Source port : %u, Destination port : %u\n",
                            ntohs(udp->uh_sport), ntohs(udp->uh_dport));

            int data_len_udp = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

            // On vérifie le port source
            switch (ntohs(udp->uh_sport)) {
            case DNS_PORT:
                got_dns(args, packet, data_len_udp);
                goto udp6_end;

            case BOOTP_PORT_CLIENT:
                got_bootp(args, packet);
                goto udp6_end;

            case BOOTP_PORT_SERVER:
                got_bootp(args, packet);
                goto udp6_end;
            }

            // On vérifie le port destination
            switch (ntohs(udp->uh_dport)) {
            case DNS_PORT:
                got_dns(args, packet, data_len_udp);
                goto udp6_end;

            case BOOTP_PORT_CLIENT:
                got_bootp(args, packet);
                goto udp6_end;

            case BOOTP_PORT_SERVER:
                got_bootp(args, packet);
                goto udp6_end;
            }
        }
    udp6_end:;
        break;

    case ETHERTYPE_ARP:
        print_verbosity(*args, 0, "%u\t\t\t\t", packet_count);
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