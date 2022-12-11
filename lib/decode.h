#pragma once
#include "arp.h"
#include "bootp.h"
#include "dns.h"
#include "ftp.h"
#include "http.h"
#include "smtp.h"
#include "tcp.h"
#include "telnet.h"
#include "verbose.h"
#include <ctype.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Function launced when a packet is captured
 *
 * @param args optional arguments
 * @param header the header of the packet
 * @param packet the packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

/**
 * @brief Decode the packets
 *
 * @param interface the interface to sniff
 * @param verbosity the verbosity level
 * @param file the file to decode
 */
void decode(char *interface, char *file, u_char verbosity);