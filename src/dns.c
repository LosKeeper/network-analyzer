#include "dns.h"

int got_dns(u_char *args, const u_char *packet) {
    // Create an offset to the DNS header
    int offset = 0;
    struct dnshdr *dns = (struct dnshdr *)(packet);
    offset += sizeof(struct dnshdr);
    print_verbosity(*args, 0, "DNS\t\t\t\t");

    if (ntohs(dns->flags) < 0x8000) {
        print_verbosity(*args, 0, "Query -> ");
        // Get the name
        for (int j = 0; j < ntohs(dns->qdcount); j++) {
            char *nameq = malloc(256);
            offset += 1;
            int i = 0;
            while (packet[offset] != 0x00) {
                if (packet[offset] == 0x03) {
                    nameq[i] = '.';
                } else {
                    nameq[i] = packet[offset];
                }
                offset += 1;
                i += 1;
            }
            offset += 1;
            struct dnsquestion *question =
                (struct dnsquestion *)(packet + offset);
            offset += sizeof(struct dnsquestion);
            // Get the DNS message type
            switch (ntohs(question->qtype)) {
            case 1:
                print_verbosity(*args, 0, "A : ");
                break;
            case 2:
                print_verbosity(*args, 0, "NS : ");
                break;
            case 5:
                print_verbosity(*args, 0, "CNAME : ");
                break;
            case 6:
                print_verbosity(*args, 0, "SOA : ");
                break;
            case 12:
                print_verbosity(*args, 0, "PTR : ");
                break;
            case 15:
                print_verbosity(*args, 0, "MX : ");
                break;
            case 16:
                print_verbosity(*args, 0, "TXT : ");
                break;
            case 28:
                print_verbosity(*args, 0, "AAAA : ");
                break;
            case 33:
                print_verbosity(*args, 0, "SRV : ");
                break;
            case 41:
                print_verbosity(*args, 0, "OPT : ");
                break;
            case 251:
                print_verbosity(*args, 0, "IXFR : ");
                break;
            case 252:
                print_verbosity(*args, 0, "AXFR : ");
                break;
            case 255:
                print_verbosity(*args, 0, "ANY : ");
                break;
            }
            // Print the query name
            print_verbosity(*args, 0, "%s, ", nameq);
            free(nameq);
        }
    }

    if (ntohs(dns->flags) >= 0x8000) {
        print_verbosity(*args, 0, "Response -> ");
        for (int j = 0; j < ntohs(dns->qdcount); j++) {
            // Get the name
            char *namer = malloc(256);
            offset += 1;
            int i = 0;
            while (packet[offset] != 0x00) {
                if (packet[offset] == 0x03) {
                    namer[i] = '.';
                } else {
                    namer[i] = packet[offset];
                }
                offset += 1;
                i += 1;
            }
            offset += 1;
            struct dnsquestion *question =
                (struct dnsquestion *)(packet + offset);
            offset += sizeof(struct dnsquestion);
            // Get the DNS message type
            switch (ntohs(question->qtype)) {
            case 1:
                print_verbosity(*args, 0, "A : ");
                break;
            case 2:
                print_verbosity(*args, 0, "NS : ");
                break;
            case 5:
                print_verbosity(*args, 0, "CNAME : ");
                break;
            case 6:
                print_verbosity(*args, 0, "SOA : ");
                break;
            case 12:
                print_verbosity(*args, 0, "PTR : ");
                break;
            case 15:
                print_verbosity(*args, 0, "MX : ");
                break;
            case 16:
                print_verbosity(*args, 0, "TXT : ");
                break;
            case 28:
                print_verbosity(*args, 0, "AAAA : ");
                break;
            case 33:
                print_verbosity(*args, 0, "SRV : ");
                break;
            case 41:
                print_verbosity(*args, 0, "OPT : ");
                break;
            case 251:
                print_verbosity(*args, 0, "IXFR : ");
                break;
            case 252:
                print_verbosity(*args, 0, "AXFR : ");
                break;
            case 255:
                print_verbosity(*args, 0, "ANY : ");
                break;
            }
            // Print the query name
            print_verbosity(*args, 0, "%s, ", namer);
            free(namer);
        }
        // Get the answers
        for (int j = 0; j < ntohs(dns->ancount); j++) {
            struct dnsanswer *answer = (struct dnsanswer *)(packet + offset);
            offset += sizeof(struct dnsanswer);
            // Get the DNS message type
            switch (ntohs(answer->type)) {
            case 1:
                print_verbosity(*args, 0, "A : ");
                break;
            case 2:
                print_verbosity(*args, 0, "NS : ");
                break;
            case 5:
                print_verbosity(*args, 0, "CNAME : ");
                break;
            case 6:
                print_verbosity(*args, 0, "SOA : ");
                break;
            case 12:
                print_verbosity(*args, 0, "PTR : ");
                break;
            case 15:
                print_verbosity(*args, 0, "MX : ");
                break;
            case 16:
                print_verbosity(*args, 0, "TXT : ");
                break;
            case 28:
                print_verbosity(*args, 0, "AAAA : ");
                break;
            case 33:
                print_verbosity(*args, 0, "SRV : ");
                break;
            case 41:
                print_verbosity(*args, 0, "OPT : ");
                break;
            case 255:
                print_verbosity(*args, 0, "ANY : ");
                break;
            }
            // Get the DNS message class
            switch (ntohs(answer->class)) {
            case 1:
                print_verbosity(*args, 0, "IN : ");
                break;
            case 2:
                print_verbosity(*args, 0, "CS : ");
                break;
            case 3:
                print_verbosity(*args, 0, "CH : ");
                break;
            case 4:
                print_verbosity(*args, 0, "HS : ");
                break;
            }
            int datalen = ntohs(answer->rdlength);
            // Get the data
            char *data = malloc(datalen + 1);
            memcpy(data, packet + offset, datalen);
            offset += datalen;
            data[datalen] = '\0';
            if (datalen == 2) {
                if (data[0] == (char)0xc0) {
                    int go_to = data[1];
                    char *namec = malloc(256);
                    int i = 0;
                    while (packet[go_to] != 0x00) {
                        if (packet[go_to] == 0x03) {
                            namec[i] = '.';
                        } else {
                            namec[i] = packet[go_to];
                        }
                        go_to += 1;
                        i += 1;
                    }
                    print_verbosity(*args, 0, "%s, ", namec);
                }
            } else if (ntohs(answer->type) == 1) {
                struct in_addr addr;
                memcpy(&addr, data, sizeof(addr));
                char *ip = malloc(INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN);
                print_verbosity(*args, 0, "%s, ", ip);
                free(ip);
            } else if (ntohs(answer->type) == 28) {
                struct in6_addr addr;
                memcpy(&addr, data, sizeof(addr));
                char *ip = malloc(INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);
                print_verbosity(*args, 0, "%s, ", ip);
                free(ip);
            } else if (data[0] == (char)0xc0) {
                int go_to = data[1];
                char *namec = malloc(256);
                int i = 0;
                while (packet[go_to] != 0x00) {
                    if (packet[go_to] == 0x03) {
                        namec[i] = '.';
                    } else {
                        namec[i] = packet[go_to];
                    }
                    go_to += 1;
                    i += 1;
                }
                print_verbosity(*args, 0, "%s, ", namec);

            } else {
                print_verbosity(*args, 0, "%s, ", data);
            }
        }
    }
    return 1;
}