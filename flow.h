#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#define MAX_FLOWS    1024
#define FLOW_TIMEOUT 30

typedef struct {
    uint32_t src_ip;      /* canonical low IP  (normalized) */
    uint32_t dst_ip;      /* canonical high IP (normalized) */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t tx_bytes;    /* bytes from original src → dst (pre-normalization) */
    uint64_t rx_bytes;    /* bytes from original dst → src (pre-normalization) */

    time_t first_seen;
    time_t last_seen;
} flow_t;

/* Called by update_flow() after each packet is recorded.
 * analysis.c registers a function here to observe every updated flow
 * without flow.c needing to know anything about detection logic. */
typedef void (*flow_observer_fn)(const flow_t *flow, uint32_t raw_src_ip,
                                 uint16_t raw_dst_port, uint32_t packet_size);
void flow_register_observer(flow_observer_fn fn);

int normalize_flow(flow_t *f);
void update_flow(flow_t *f, uint32_t packet_size, uint32_t raw_src_ip,
                 uint16_t raw_dst_port);
void print_flows(void);
void expire_flows(void);

#endif

/* Returns total bytes seen across all flows this session.
 * Used by analysis.c for elephant flow threshold calculation. */
uint64_t flow_total_bytes(void);

/* Write all active flows to a CSV file.
 * Called on exit so data survives after Ctrl+C. */
void export_flows_csv(const char *path);
