#include "flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define FNV_OFFSET  2166136261u
#define FNV_PRIME   16777619u
#define TABLE_SIZE  4096
#define TABLE_MASK  (TABLE_SIZE - 1)

typedef enum {
    SLOT_EMPTY,
    SLOT_OCCUPIED,
    SLOT_DELETED
} slot_state_t;

typedef struct {
    slot_state_t state;
    flow_t flow;
} slot_t;

static uint64_t tcp_bytes   = 0;
static uint64_t udp_bytes   = 0;
static uint64_t dns_bytes   = 0;
static uint64_t https_bytes = 0;

static slot_t table[TABLE_SIZE];
static int    flow_count = 0;

static flow_observer_fn g_observer = NULL;

void flow_register_observer(flow_observer_fn fn)
{
    g_observer = fn;
}

/* FNV-1a over the 5-tuple */
static uint32_t hash_flow(const flow_t *f)
{
    uint32_t h = FNV_OFFSET;
    const uint8_t *p;

    p = (const uint8_t *)&f->src_ip;
    for (int i = 0; i < 4; i++) { h ^= p[i]; h *= FNV_PRIME; }

    p = (const uint8_t *)&f->dst_ip;
    for (int i = 0; i < 4; i++) { h ^= p[i]; h *= FNV_PRIME; }

    p = (const uint8_t *)&f->src_port;
    for (int i = 0; i < 2; i++) { h ^= p[i]; h *= FNV_PRIME; }

    p = (const uint8_t *)&f->dst_port;
    for (int i = 0; i < 2; i++) { h ^= p[i]; h *= FNV_PRIME; }

    h ^= f->protocol;
    h *= FNV_PRIME;

    return h;
}

static slot_t *ht_find(const flow_t *key)
{
    uint32_t idx = hash_flow(key) & TABLE_MASK;

    for (int i = 0; i < TABLE_SIZE; i++) {
        slot_t *slot = &table[(idx + i) & TABLE_MASK];

        if (slot->state == SLOT_EMPTY)
            return NULL;

        if (slot->state == SLOT_OCCUPIED &&
            slot->flow.src_ip   == key->src_ip   &&
            slot->flow.dst_ip   == key->dst_ip   &&
            slot->flow.src_port == key->src_port &&
            slot->flow.dst_port == key->dst_port &&
            slot->flow.protocol == key->protocol)
            return slot;
    }
    return NULL;
}

static slot_t *ht_insert(const flow_t *key)
{
    if (flow_count >= (int)(TABLE_SIZE * 0.7)) {
        fprintf(stderr, "flow table over 70%% capacity\n");
        return NULL;
    }

    uint32_t idx = hash_flow(key) & TABLE_MASK;
    slot_t *tombstone = NULL;

    for (int i = 0; i < TABLE_SIZE; i++) {
        slot_t *slot = &table[(idx + i) & TABLE_MASK];

        if (slot->state == SLOT_DELETED && tombstone == NULL) {
            tombstone = slot;
            continue;
        }

        if (slot->state == SLOT_EMPTY) {
            slot_t *target = tombstone ? tombstone : slot;
            target->state = SLOT_OCCUPIED;
            target->flow  = *key;
            target->flow.first_seen   = 0;
            target->flow.last_seen    = 0;
            target->flow.packet_count = 0;
            target->flow.byte_count   = 0;
            target->flow.tx_bytes     = 0;
            target->flow.rx_bytes     = 0;
            flow_count++;
            return target;
        }
    }

    /* Table full despite load check — shouldn't happen, but be safe */
    if (tombstone) {
        tombstone->state = SLOT_OCCUPIED;
        tombstone->flow  = *key;
        tombstone->flow.first_seen   = 0;
        tombstone->flow.last_seen    = 0;
        tombstone->flow.packet_count = 0;
        tombstone->flow.byte_count   = 0;
        tombstone->flow.tx_bytes     = 0;
        tombstone->flow.rx_bytes     = 0;
        flow_count++;
        return tombstone;
    }
    return NULL;
}

static void ht_delete(slot_t *slot)   /* was wrongly declared void* */
{
    slot->state = SLOT_DELETED;
    flow_count--;
}

/* Normalize to canonical (low-ip, low-port) order.
 * Returns 1 if src/dst were swapped (caller uses this for tx/rx accounting). */
int normalize_flow(flow_t *f)
{
    if (f->src_ip > f->dst_ip ||
       (f->src_ip == f->dst_ip && f->src_port > f->dst_port)) {

        uint32_t tmp_ip   = f->src_ip;   f->src_ip   = f->dst_ip;   f->dst_ip   = tmp_ip;
        uint16_t tmp_port = f->src_port; f->src_port = f->dst_port; f->dst_port = tmp_port;
        return 1;   /* swapped */
    }
    return 0;       /* not swapped */
}

void expire_flows(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (table[i].state != SLOT_OCCUPIED)
            continue;
        if (now - table[i].flow.last_seen > FLOW_TIMEOUT)
            ht_delete(&table[i]);
    }
}

static const char *classify_protocol(uint8_t proto, uint16_t sport, uint16_t dport)
{
    uint16_t port = sport < dport ? sport : dport;

    if (proto == IPPROTO_TCP) {
        if (port == 80)  return "HTTP";
        if (port == 443) return "HTTPS";
        if (port == 22)  return "SSH";
    }
    if (proto == IPPROTO_UDP) {
        if (port == 53)  return "DNS";
        if (port == 443) return "QUIC";
    }
    return (proto == IPPROTO_TCP) ? "TCP" :
           (proto == IPPROTO_UDP) ? "UDP" : "OTHER";
}

static void format_bytes(uint64_t bytes, char *buf, size_t len)
{
    if      (bytes >= 1073741824) snprintf(buf, len, "%.1f GB", bytes / 1073741824.0);
    else if (bytes >= 1048576)    snprintf(buf, len, "%.1f MB", bytes / 1048576.0);
    else if (bytes >= 1024)       snprintf(buf, len, "%.1f KB", bytes / 1024.0);
    else                          snprintf(buf, len, "%lu B",   (unsigned long)bytes);
}

static void format_duration(time_t first_seen, time_t last_seen, char *buf, size_t len)
{
    time_t diff = last_seen - first_seen;
    if (diff < 0) diff = 0;
    snprintf(buf, len, "%02d:%02d:%02d",
             (int)(diff / 3600), (int)((diff % 3600) / 60), (int)(diff % 60));
}

static int cmp_bytes(const void *a, const void *b)
{
    const flow_t *fa = (const flow_t *)a;
    const flow_t *fb = (const flow_t *)b;
    if (fb->byte_count > fa->byte_count) return  1;
    if (fb->byte_count < fa->byte_count) return -1;
    return 0;
}

void update_flow(flow_t *f, uint32_t packet_size,
                 uint32_t raw_src_ip, uint16_t raw_dst_port)
{
    /* Accumulate protocol totals before normalization changes the ports */
    if (f->protocol == IPPROTO_TCP) tcp_bytes += packet_size;
    if (f->protocol == IPPROTO_UDP) udp_bytes += packet_size;

    /* Fixed: parentheses now enforce correct precedence */
    if (f->protocol == IPPROTO_UDP && (f->src_port == 53 || f->dst_port == 53))
        dns_bytes += packet_size;
    if (f->src_port == 443 || f->dst_port == 443)
        https_bytes += packet_size;

    int swapped = normalize_flow(f);

    slot_t *slot = ht_find(f);
    if (!slot) {
        slot = ht_insert(f);
        if (!slot) return;
        time_t now = time(NULL);
        slot->flow.first_seen = now;
        slot->flow.last_seen  = now;
    } else {
        slot->flow.last_seen = time(NULL);
    }

    slot->flow.packet_count++;
    slot->flow.byte_count += packet_size;

    /* tx = bytes leaving raw_src; rx = bytes arriving at raw_src */
    if (!swapped) slot->flow.tx_bytes += packet_size;
    else          slot->flow.rx_bytes += packet_size;

    if (g_observer)
        g_observer(&slot->flow, raw_src_ip, raw_dst_port, packet_size);
}

void print_flows(void)
{
    /* Static to avoid a ~180 KB stack frame (4096 * sizeof flow_t) */
    static flow_t sorted[TABLE_SIZE];
    int count = 0;

    printf("\033[H\033[J");

    uint64_t total = tcp_bytes + udp_bytes;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("==== NETMON | flows: %d | %02d:%02d:%02d ====\n\n",
           flow_count, t->tm_hour, t->tm_min, t->tm_sec);

    for (int i = 0; i < TABLE_SIZE; i++)
        if (table[i].state == SLOT_OCCUPIED)
            sorted[count++] = table[i].flow;

    qsort(sorted, count, sizeof(flow_t), cmp_bytes);

    if (total > 0) {
        printf("Protocol Breakdown:\n");
        printf("  TCP:   %.2f%%\n", (tcp_bytes   * 100.0) / total);
        printf("  UDP:   %.2f%%\n", (udp_bytes   * 100.0) / total);
        printf("  DNS:   %.2f%%\n", (dns_bytes   * 100.0) / total);
        printf("  HTTPS: %.2f%%\n", (https_bytes * 100.0) / total);
    }

    printf("\n  %-22s %-22s %-6s %-8s %-10s %-10s %-12s %-10s\n",
           "SRC", "DST", "PROTO", "PKTS", "TX", "RX", "DURATION", "BPS");

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    char src_buf[32], dst_buf[32], tx_buf[16], rx_buf[16], dur_buf[16];

    for (int i = 0; i < count; i++) {
        flow_t *f = &sorted[i];

        /* Display the heavier-sending side as SRC so TX is never 0.
         * Canonical normalization (low IP first) is the hash key only —
         * for display, traffic direction matters more. */
        uint32_t disp_src_ip   = f->src_ip,   disp_dst_ip   = f->dst_ip;
        uint16_t disp_src_port = f->src_port, disp_dst_port = f->dst_port;
        uint64_t disp_tx       = f->tx_bytes, disp_rx       = f->rx_bytes;
        if (f->rx_bytes > f->tx_bytes) {
            disp_src_ip   = f->dst_ip;   disp_dst_ip   = f->src_ip;
            disp_src_port = f->dst_port; disp_dst_port = f->src_port;
            disp_tx       = f->rx_bytes; disp_rx       = f->tx_bytes;
        }

        inet_ntop(AF_INET, &disp_src_ip, src, sizeof(src));
        inet_ntop(AF_INET, &disp_dst_ip, dst, sizeof(dst));
        snprintf(src_buf, sizeof(src_buf), "%s:%d", src, disp_src_port);
        snprintf(dst_buf, sizeof(dst_buf), "%s:%d", dst, disp_dst_port);
        format_bytes(disp_tx, tx_buf, sizeof(tx_buf));
        format_bytes(disp_rx, rx_buf, sizeof(rx_buf));
        format_duration(f->first_seen, f->last_seen, dur_buf, sizeof(dur_buf));

        double duration = difftime(f->last_seen, f->first_seen);
        if (duration <= 0) duration = 1;
        double bps = (f->byte_count * 8.0) / duration;

        /* Mark flows silent for > 3s so stale BPS is visually distinct */
        time_t age = now - f->last_seen;
        const char *stale = (age > 3) ? " ~" : "  ";

        printf("  %-22s %-22s %-6s %-8lu %-10s %-10s %-12s %-10.0f%s\n",
               src_buf, dst_buf,
               classify_protocol(f->protocol, disp_src_port, disp_dst_port),
               (unsigned long)f->packet_count,
               tx_buf, rx_buf, dur_buf, bps, stale);
    }

    fflush(stdout);   /* flush atomically so frames don't interleave */
}

uint64_t flow_total_bytes(void)
{
    return tcp_bytes + udp_bytes;
}

void export_flows_csv(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("export_flows_csv: fopen");
        return;
    }

    fprintf(f, "src_ip,src_port,dst_ip,dst_port,protocol,"
               "packets,bytes,tx_bytes,rx_bytes,"
               "first_seen,last_seen,duration_s\n");

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    for (int i = 0; i < TABLE_SIZE; i++) {
        if (table[i].state != SLOT_OCCUPIED)
            continue;

        flow_t *fl = &table[i].flow;

        /* Display direction: heavier sender first, same as print_flows */
        uint32_t sip = fl->src_ip, dip = fl->dst_ip;
        uint16_t sp  = fl->src_port, dp = fl->dst_port;
        uint64_t tx  = fl->tx_bytes, rx = fl->rx_bytes;
        if (fl->rx_bytes > fl->tx_bytes) {
            sip = fl->dst_ip;  dip = fl->src_ip;
            sp  = fl->dst_port; dp = fl->src_port;
            tx  = fl->rx_bytes; rx = fl->tx_bytes;
        }

        inet_ntop(AF_INET, &sip, src, sizeof(src));
        inet_ntop(AF_INET, &dip, dst, sizeof(dst));

        time_t dur = fl->last_seen - fl->first_seen;
        if (dur < 0) dur = 0;

        fprintf(f, "%s,%u,%s,%u,%u,%lu,%lu,%lu,%lu,%ld,%ld,%ld\n",
                src, sp, dst, dp, fl->protocol,
                (unsigned long)fl->packet_count,
                (unsigned long)fl->byte_count,
                (unsigned long)tx,
                (unsigned long)rx,
                (long)fl->first_seen,
                (long)fl->last_seen,
                (long)dur);
    }

    fclose(f);
    printf("\n[+] flows exported to %s\n", path);
}