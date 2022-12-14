#include "dns.h"

int got_dns(u_char *args, const u_char *packet, int data_len) {
    // Create an offset to the DNS header
    int offset = 0;
    struct dnshdr *dns = (struct dnshdr *)(packet);
    offset += sizeof(struct dnshdr);
    // Vebosity 0
    print_verbosity(*args, 0, "DNS\t\t\t\t");

    // Verbosity 1
    print_verbosity(*args, 1, "\033[32m");
    print_verbosity(*args, 1, "DNS : ");
    print_verbosity(*args, 1, "\033[0m");

    if (ntohs(dns->flags) < 0x8000) {
        print_verbosity(*args, 0, "Query -> ");
        print_verbosity(*args, 1, "Query -> ");
        // Get the name
        // Only print the first query for the verbosity 0
        for (int j = 0; j < ntohs(dns->qdcount); j++) {
            char *nameq = malloc(256);
            offset += 1;
            int i = 0;
            while (packet[offset] != 0x00) {
                if (packet[offset] == 0x03) {
                    nameq[i] = '.';
                } else if (isprint(packet[offset]) && offset < data_len) {
                    nameq[i] = packet[offset];
                }
                offset += 1;
                i += 1;
            }
            offset += 1;
            nameq[i] = '\0';
            struct dnsquestion *question =
                (struct dnsquestion *)(packet + offset);
            offset += sizeof(struct dnsquestion);
            // Get the DNS message type
            switch (ntohs(question->qtype)) {
            case 1:
                print_verbosity(*args, 0, "A : ");
                print_verbosity(*args, 1, "A : ");
                break;
            case 2:
                print_verbosity(*args, 0, "NS : ");
                print_verbosity(*args, 1, "NS : ");
                break;
            case 5:
                print_verbosity(*args, 0, "CNAME : ");
                print_verbosity(*args, 1, "CNAME : ");
                break;
            case 6:
                print_verbosity(*args, 0, "SOA : ");
                print_verbosity(*args, 1, "SOA : ");
                break;
            case 12:
                print_verbosity(*args, 0, "PTR : ");
                print_verbosity(*args, 1, "PTR : ");
                break;
            case 15:
                print_verbosity(*args, 0, "MX : ");
                print_verbosity(*args, 1, "MX : ");
                break;
            case 16:
                print_verbosity(*args, 0, "TXT : ");
                print_verbosity(*args, 1, "TXT : ");
                break;
            case 28:
                print_verbosity(*args, 0, "AAAA : ");
                print_verbosity(*args, 1, "AAAA : ");
                break;
            case 33:
                print_verbosity(*args, 0, "SRV : ");
                print_verbosity(*args, 1, "SRV : ");
                break;
            case 41:
                print_verbosity(*args, 0, "OPT : ");
                print_verbosity(*args, 1, "OPT : ");
                break;
            case 251:
                print_verbosity(*args, 0, "IXFR : ");
                print_verbosity(*args, 1, "IXFR : ");
                break;
            case 252:
                print_verbosity(*args, 0, "AXFR : ");
                print_verbosity(*args, 1, "AXFR : ");
                break;
            case 255:
                print_verbosity(*args, 0, "ANY : ");
                print_verbosity(*args, 1, "ANY : ");
                break;
            }
            // Print the query name
            print_verbosity(*args, 0, "%s,... ", nameq);
            print_verbosity(*args, 1, "%s, ", nameq);
            free(nameq);
            if (*args == 0) {
                goto dns_end;
            }
        }
    }
    if (ntohs(dns->flags) >= 0x8080) {
        print_verbosity(*args, 0, "Response -> ");
        print_verbosity(*args, 1, "Response -> ");
        // Only print the first answer for the verbosity 0
        for (int j = 0; j < ntohs(dns->qdcount); j++) {
            // Get the name
            char *namer = malloc(256);
            offset += 1;
            int i = 0;
            while (packet[offset] != 0x00) {
                if (packet[offset] == 0x03) {
                    namer[i] = '.';
                } else if (isprint(packet[offset]) && offset < data_len) {
                    namer[i] = packet[offset];
                }
                offset += 1;
                i += 1;
            }
            offset += 1;
            namer[i] = '\0';
            struct dnsquestion *question =
                (struct dnsquestion *)(packet + offset);
            offset += sizeof(struct dnsquestion);
            // Get the DNS message type
            switch (ntohs(question->qtype)) {
            case 1:
                print_verbosity(*args, 0, "A : ");
                print_verbosity(*args, 1, "A : ");
                break;
            case 2:
                print_verbosity(*args, 0, "NS : ");
                print_verbosity(*args, 1, "NS : ");
                break;
            case 5:
                print_verbosity(*args, 0, "CNAME : ");
                print_verbosity(*args, 1, "CNAME : ");
                break;
            case 6:
                print_verbosity(*args, 0, "SOA : ");
                print_verbosity(*args, 1, "SOA : ");
                break;
            case 12:
                print_verbosity(*args, 0, "PTR : ");
                print_verbosity(*args, 1, "PTR : ");
                break;
            case 15:
                print_verbosity(*args, 0, "MX : ");
                print_verbosity(*args, 1, "MX : ");
                break;
            case 16:
                print_verbosity(*args, 0, "TXT : ");
                print_verbosity(*args, 1, "TXT : ");
                break;
            case 28:
                print_verbosity(*args, 0, "AAAA : ");
                print_verbosity(*args, 1, "AAAA : ");
                break;
            case 33:
                print_verbosity(*args, 0, "SRV : ");
                print_verbosity(*args, 1, "SRV : ");
                break;
            case 41:
                print_verbosity(*args, 0, "OPT : ");
                print_verbosity(*args, 1, "OPT : ");
                break;
            case 251:
                print_verbosity(*args, 0, "IXFR : ");
                print_verbosity(*args, 1, "IXFR : ");
                break;
            case 252:
                print_verbosity(*args, 0, "AXFR : ");
                print_verbosity(*args, 1, "AXFR : ");
                break;
            case 255:
                print_verbosity(*args, 0, "ANY : ");
                print_verbosity(*args, 1, "ANY : ");
                break;
            }
            // Print the query name
            print_verbosity(*args, 0, "%s,...", namer);
            print_verbosity(*args, 1, "%s, ", namer);
            free(namer);
            if (*args == 0) {
                goto dns_end;
            }
        }
        // Get the answers
        for (int j = 0; j < ntohs(dns->ancount); j++) {
            // Only print the first answer for verbosity 0
            struct dnsanswer *answer = (struct dnsanswer *)(packet + offset);
            offset += sizeof(struct dnsanswer);
            // Get the DNS message type
            switch (ntohs(answer->type)) {
            case 1:
                print_verbosity(*args, 0, "A : ");
                print_verbosity(*args, 1, "A : ");
                break;
            case 2:
                print_verbosity(*args, 0, "NS : ");
                print_verbosity(*args, 1, "NS : ");
                break;
            case 5:
                print_verbosity(*args, 0, "CNAME : ");
                print_verbosity(*args, 1, "CNAME : ");
                break;
            case 6:
                print_verbosity(*args, 0, "SOA : ");
                print_verbosity(*args, 1, "SOA : ");
                break;
            case 12:
                print_verbosity(*args, 0, "PTR : ");
                print_verbosity(*args, 1, "PTR : ");
                break;
            case 15:
                print_verbosity(*args, 0, "MX : ");
                print_verbosity(*args, 1, "MX : ");
                break;
            case 16:
                print_verbosity(*args, 0, "TXT : ");
                print_verbosity(*args, 1, "TXT : ");
                break;
            case 28:
                print_verbosity(*args, 0, "AAAA : ");
                print_verbosity(*args, 1, "AAAA : ");
                break;
            case 33:
                print_verbosity(*args, 0, "SRV : ");
                print_verbosity(*args, 1, "SRV : ");
                break;
            case 41:
                print_verbosity(*args, 0, "OPT : ");
                print_verbosity(*args, 1, "OPT : ");
                break;
            case 255:
                print_verbosity(*args, 0, "ANY : ");
                print_verbosity(*args, 1, "ANY : ");
                break;
            }
            // Get the DNS message class
            switch (ntohs(answer->class)) {
            case 1:
                print_verbosity(*args, 0, "IN : ");
                print_verbosity(*args, 1, "IN : ");
                break;
            case 2:
                print_verbosity(*args, 0, "CS : ");
                print_verbosity(*args, 1, "CS : ");
                break;
            case 3:
                print_verbosity(*args, 0, "CH : ");
                print_verbosity(*args, 1, "CH : ");
                break;
            case 4:
                print_verbosity(*args, 0, "HS : ");
                print_verbosity(*args, 1, "HS : ");
                break;
            }
            int datalen = ntohs(answer->rdlength);
            // Get the data
            char *data = malloc(datalen + 1);
            memcpy(data, packet + offset, datalen);
            offset += datalen;
            if (offset > data_len) {
                free(data);
                goto dns_end;
            }
            data[datalen] = '\0';
            if (ntohs(answer->type) == 1) {
                struct in_addr addr;
                memcpy(&addr, data, sizeof(addr));
                char *ip = malloc(INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN);
                print_verbosity(*args, 0, "%s,... ", ip);
                print_verbosity(*args, 1, "%s, ", ip);
                free(ip);
            } else if (ntohs(answer->type) == 28) {
                struct in6_addr addr;
                memcpy(&addr, data, sizeof(addr));
                char *ip = malloc(INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);
                print_verbosity(*args, 0, "%s,... ", ip);
                print_verbosity(*args, 1, "%s, ", ip);
                free(ip);
            } else if (data[0] == (char)0xc0) {
                int go_to = data[1];
                char *named = malloc(256);
                int i = 0;
                while (packet[go_to] != 0x00) {
                    if (packet[go_to] == 0x03) {
                        named[i] = '.';
                        i += 1;
                    } else if (isprint(packet[go_to])) {
                        named[i] = packet[go_to];
                        i += 1;
                    }
                    go_to += 1;
                }
                named[i] = '\0';
                print_verbosity(*args, 0, "%s,... ", named);
                print_verbosity(*args, 1, "%s, ", named);
                free(named);

            } else {
                int i = 1;
                while (isprint(data[i]) && i < datalen) {
                    print_verbosity(*args, 0, "%c", data[i]);
                    print_verbosity(*args, 1, "%c", data[i]);
                    i += 1;
                }
                print_verbosity(*args, 0, ",...");
                print_verbosity(*args, 1, ", ");
            }
            if (*args == 0) {
                goto dns_end;
            }
        }
    }
dns_end:;
    packet += offset;
    return 1;
}