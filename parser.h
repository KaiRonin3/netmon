#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>

void parse_packet(const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif
