#include "parser.h"
#include "flow.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

void parse_packet(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    if (header->caplen < sizeof(struct ether_header))
        return;

    const struct ether_header *eth = (const struct ether_header *)pkt_data;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    const struct ip *ih = (const struct ip *)(pkt_data + sizeof(struct ether_header));
    int ip_hlen = ih->ip_hl * 4;

    if (header->caplen < sizeof(struct ether_header) + (unsigned)ip_hlen)
        return;

    int offset = sizeof(struct ether_header) + ip_hlen;

    flow_t f;
    f.src_ip   = ih->ip_src.s_addr;
    f.dst_ip   = ih->ip_dst.s_addr;
    f.protocol = ih->ip_p;

    uint32_t raw_src_ip   = ih->ip_src.s_addr;
    uint16_t raw_dst_port = 0;

    if (ih->ip_p == IPPROTO_TCP) {
        if (header->caplen < (unsigned)(offset + (int)sizeof(struct tcphdr)))
            return;
        const struct tcphdr *th = (const struct tcphdr *)(pkt_data + offset);
        f.src_port    = ntohs(th->th_sport);
        f.dst_port    = ntohs(th->th_dport);
        raw_dst_port  = ntohs(th->th_dport);

    } else if (ih->ip_p == IPPROTO_UDP) {
        if (header->caplen < (unsigned)(offset + (int)sizeof(struct udphdr)))
            return;
        const struct udphdr *uh = (const struct udphdr *)(pkt_data + offset);
        f.src_port   = ntohs(uh->uh_sport);
        f.dst_port   = ntohs(uh->uh_dport);
        raw_dst_port = ntohs(uh->uh_dport);

    } else {
        return;  /* unsupported protocol */
    }

    update_flow(&f, header->len, raw_src_ip, raw_dst_port);

    static time_t last_print = 0;
    time_t now = time(NULL);
    if (now != last_print) {
        last_print = now;
        print_flows();
    }
}