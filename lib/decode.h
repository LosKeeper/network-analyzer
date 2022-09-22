#pragma once
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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
 */
void decode(char *interface);