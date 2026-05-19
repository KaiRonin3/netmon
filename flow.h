#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <time.h>

#define MAX_FLOWS 1024
#define FLOW_TIMEOUT 30

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    uint64_t packet_count;
    uint64_t byte_count;

    time_t first_seen;
    time_t last_seen;
} flow_t;

void normalize_flow(flow_t *f);
void update_flow(flow_t *f, uint32_t packet_size);
void print_flows();
void expire_flows();

#endif