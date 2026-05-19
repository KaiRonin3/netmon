#include "parser.h"
#include "flow.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

void parse_packet(const struct pcap_pkthdr *header,
                  const u_char *pkt_data)
{
    if (header->caplen < sizeof(struct ether_header))
        return;

    struct ether_header *eth = (struct ether_header*)pkt_data;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    struct ip *ih = (struct ip*)(pkt_data + sizeof(struct ether_header));

    int ip_header_len = ih->ip_hl * 4;

    if (header->caplen < sizeof(struct ether_header) + ip_header_len)
        return;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ih->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ih->ip_dst), dst_ip, INET_ADDRSTRLEN);

    int offset = sizeof(struct ether_header) + ip_header_len;

    if (ih->ip_p == IPPROTO_TCP) {

        if (header->caplen < offset + sizeof(struct tcphdr))
            return;

        struct tcphdr *th = (struct tcphdr*)(pkt_data + offset);

        uint16_t sport = ntohs(th->th_sport);
        uint16_t dport = ntohs(th->th_dport);

        flow_t f;

        f.src_ip = ih->ip_src.s_addr;
        f.dst_ip = ih->ip_dst.s_addr;
        f.src_port = sport;
        f.dst_port = dport;
        f.protocol = ih->ip_p;

        normalize_flow(&f);
        update_flow(&f, header->len);
    }
    
    else if (ih->ip_p == IPPROTO_UDP) {

        if (header->caplen < offset + sizeof(struct udphdr))
            return;

        struct udphdr *uh = (struct udphdr*)(pkt_data + offset);

        uint16_t sport = ntohs(uh->uh_sport);
        uint16_t dport = ntohs(uh->uh_dport);

        flow_t f;

        f.src_ip = ih->ip_src.s_addr;
        f.dst_ip = ih->ip_dst.s_addr;
        f.src_port = sport;
        f.dst_port = dport;
        f.protocol = ih->ip_p;

        normalize_flow(&f);
        update_flow(&f, header->len);
    }

    static int counter = 0;
    counter++;

    if (counter % 50 == 0) {
        print_flows();
    }
}