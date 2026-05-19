

#include "analysis.h"
#include "flow.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ── tunables ─────────────────────────────────────────────────────────────── */

#define SCAN_MAX_TRACKERS    64
#define SCAN_MAX_PORTS       256
#define SCAN_PORT_THRESHOLD  20    /* distinct dst ports before alert */
#define SCAN_WINDOW          60    /* seconds */

#define FLOOD_MAX_TRACKERS   64
#define FLOOD_MAX_FLOWS      512
#define FLOOD_FLOW_THRESHOLD 80    /* new TCP flows per window before alert */
#define FLOOD_WINDOW         10    /* seconds */

#define EXFIL_RATIO          5.0   /* tx must be N× rx to trigger */
#define EXFIL_MIN_BYTES      (1024 * 1024)  /* 1 MB minimum to reduce FP */

/* ── port scan detector ───────────────────────────────────────────────────── */

typedef struct {
    uint32_t src_ip;
    uint16_t ports[SCAN_MAX_PORTS];
    int      count;
    time_t   window_start;
    int      alerted;
} scan_tracker_t;

static scan_tracker_t scan_trackers[SCAN_MAX_TRACKERS];
static int            scan_tracker_count = 0;

static void detect_port_scan(uint32_t raw_src_ip, uint16_t raw_dst_port)
{
    time_t now = time(NULL);

    /* Find existing tracker for this source */
    scan_tracker_t *tr = NULL;
    for (int i = 0; i < scan_tracker_count; i++) {
        if (scan_trackers[i].src_ip == raw_src_ip) {
            tr = &scan_trackers[i];
            break;
        }
    }

    /* Allocate new tracker if none found */
    if (!tr) {
        if (scan_tracker_count >= SCAN_MAX_TRACKERS)
            return;  /* table full — drop silently */
        tr = &scan_trackers[scan_tracker_count++];
        tr->src_ip       = raw_src_ip;
        tr->count        = 0;
        tr->window_start = now;
        tr->alerted      = 0;
    }

    /* Reset window if expired */
    if (now - tr->window_start > SCAN_WINDOW) {
        tr->count        = 0;
        tr->window_start = now;
        tr->alerted      = 0;
    }

    /* Skip if we've already alerted this window */
    if (tr->alerted)
        return;

    /* Check whether this port is already recorded */
    for (int j = 0; j < tr->count; j++)
        if (tr->ports[j] == raw_dst_port)
            return;

    /* Bounds-checked port insert */
    if (tr->count < SCAN_MAX_PORTS)
        tr->ports[tr->count++] = raw_dst_port;

    if (tr->count >= SCAN_PORT_THRESHOLD) {
        struct in_addr addr = { .s_addr = raw_src_ip };
        printf("\n[!] PORT SCAN  src=%-15s  %d distinct ports in %ds\n",
               inet_ntoa(addr), tr->count, SCAN_WINDOW);
        tr->alerted = 1;
    }
}

/* ── SYN flood detector ───────────────────────────────────────────────────── */

typedef struct {
    uint32_t src_ip;
    time_t   flow_times[FLOOD_MAX_FLOWS];  /* ring buffer of new-flow timestamps */
    int      head;
    int      count;
    int      alerted;
} flood_tracker_t;

static flood_tracker_t flood_trackers[FLOOD_MAX_TRACKERS];
static int             flood_tracker_count = 0;

static void detect_syn_flood(const flow_t *flow, uint32_t raw_src_ip)
{
    /* Only track TCP flows, and only on the first packet (new flow) */
    if (flow->protocol != IPPROTO_TCP || flow->packet_count != 1)
        return;

    time_t now = time(NULL);

    flood_tracker_t *tr = NULL;
    for (int i = 0; i < flood_tracker_count; i++) {
        if (flood_trackers[i].src_ip == raw_src_ip) {
            tr = &flood_trackers[i];
            break;
        }
    }

    if (!tr) {
        if (flood_tracker_count >= FLOOD_MAX_TRACKERS)
            return;
        tr = &flood_trackers[flood_tracker_count++];
        tr->src_ip  = raw_src_ip;
        tr->head    = 0;
        tr->count   = 0;
        tr->alerted = 0;
    }

    /* Insert this new-flow timestamp into the ring buffer */
    if (tr->count < FLOOD_MAX_FLOWS) {
        tr->flow_times[tr->head] = now;
        tr->head  = (tr->head + 1) % FLOOD_MAX_FLOWS;
        tr->count++;
    }

    /* Count how many of the recorded flows fall within the window */
    int window_count = 0;
    for (int i = 0; i < tr->count; i++)
        if (now - tr->flow_times[i] <= FLOOD_WINDOW)
            window_count++;

    /* Reset alert flag when activity drops back below threshold */
    if (window_count < FLOOD_FLOW_THRESHOLD)
        tr->alerted = 0;

    if (!tr->alerted && window_count >= FLOOD_FLOW_THRESHOLD) {
        struct in_addr addr = { .s_addr = raw_src_ip };
        printf("\n[!] SYN FLOOD  src=%-15s  %d new TCP flows in %ds\n",
               inet_ntoa(addr), window_count, FLOOD_WINDOW);
        tr->alerted = 1;
    }
}

/* ── data exfiltration detector ───────────────────────────────────────────── */

static void detect_exfiltration(const flow_t *flow)
{
    if (flow->rx_bytes == 0)
        return;  /* avoid divide-by-zero; also no inbound = not meaningful */

    if (flow->byte_count < EXFIL_MIN_BYTES)
        return;

    double ratio = (double)flow->tx_bytes / (double)flow->rx_bytes;
    if (ratio < EXFIL_RATIO)
        return;

    /* Only alert once per flow (when it first crosses both thresholds).
     * Use tx_bytes crossing the min as the edge trigger to avoid
     * re-alerting on every subsequent packet. */
    if (flow->tx_bytes - (uint64_t)(flow->rx_bytes * EXFIL_RATIO) >
        (uint64_t)(EXFIL_MIN_BYTES * 0.1))
        return;  /* well past the threshold edge — already would have alerted */

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &flow->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &flow->dst_ip, dst, sizeof(dst));

    printf("\n[!] EXFILTRATION?  %s:%d → %s:%d  "
           "tx=%.1f KB  rx=%.1f KB  ratio=%.1fx\n",
           src, flow->src_port, dst, flow->dst_port,
           flow->tx_bytes / 1024.0, flow->rx_bytes / 1024.0, ratio);
}

/* forward declaration — defined after the observer callback */
static void detect_elephant(const flow_t *flow);

/* ── observer callback (registered with flow.c) ───────────────────────────── */

static void on_flow_update(const flow_t *flow, uint32_t raw_src_ip,
                           uint16_t raw_dst_port, uint32_t packet_size)
{
    (void)packet_size;  /* unused for now */
    detect_port_scan(raw_src_ip, raw_dst_port);
    detect_syn_flood(flow, raw_src_ip);
    detect_exfiltration(flow);
    detect_elephant(flow);
}

void analysis_init(void)
{
    flow_register_observer(on_flow_update);
}

/* ── elephant flow detector ───────────────────────────────────────────────── */
/*
 * An elephant flow is one that dominates total session traffic.
 * Common threshold in literature is 10% of total bytes.
 * We alert once per flow (tracked by src_ip+src_port+dst_ip+dst_port)
 * when it first crosses the threshold, to avoid spamming.
 *
 * Because flows are normalized (low IP first), we key on the canonical
 * 4-tuple stored in flow_t, not the display-direction version.
 */

#define ELEPHANT_THRESHOLD   0.10   /* fraction of total session bytes */
#define ELEPHANT_MIN_BYTES   (512 * 1024)  /* 512 KB floor to ignore tiny sessions */
#define ELEPHANT_MAX_TRACKED 128

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} flow_key_t;

static flow_key_t elephant_alerted[ELEPHANT_MAX_TRACKED];
static int        elephant_alerted_count = 0;

static int elephant_already_alerted(const flow_t *flow)
{
    for (int i = 0; i < elephant_alerted_count; i++) {
        flow_key_t *k = &elephant_alerted[i];
        if (k->src_ip   == flow->src_ip   &&
            k->dst_ip   == flow->dst_ip   &&
            k->src_port == flow->src_port &&
            k->dst_port == flow->dst_port)
            return 1;
    }
    return 0;
}

static void detect_elephant(const flow_t *flow)
{
    if (flow->byte_count < ELEPHANT_MIN_BYTES)
        return;

    uint64_t total = flow_total_bytes();
    if (total == 0)
        return;

    double fraction = (double)flow->byte_count / (double)total;
    if (fraction < ELEPHANT_THRESHOLD)
        return;

    if (elephant_already_alerted(flow))
        return;

    if (elephant_alerted_count < ELEPHANT_MAX_TRACKED) {
        flow_key_t *k = &elephant_alerted[elephant_alerted_count++];
        k->src_ip   = flow->src_ip;
        k->dst_ip   = flow->dst_ip;
        k->src_port = flow->src_port;
        k->dst_port = flow->dst_port;
    }

    /* Display in traffic direction (heavier sender first) */
    uint32_t sip = flow->src_ip, dip = flow->dst_ip;
    uint16_t sp  = flow->src_port, dp = flow->dst_port;
    if (flow->rx_bytes > flow->tx_bytes) {
        sip = flow->dst_ip;  dip = flow->src_ip;
        sp  = flow->dst_port; dp = flow->src_port;
    }

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sip, src, sizeof(src));
    inet_ntop(AF_INET, &dip, dst, sizeof(dst));

    printf("\n[!] ELEPHANT FLOW  %s:%d → %s:%d  "
           "%.1f MB  (%.1f%% of session traffic)\n",
           src, sp, dst, dp,
           flow->byte_count / 1048576.0,
           fraction * 100.0);
}