#include "flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

#define FNV_OFFSET 2166136261u
#define FNV_PRIME 16777619u
#define TABLE_SIZE 4096
#define TABLE_MASK (TABLE_SIZE -1)

typedef enum{
	SLOT_EMPTY, // unused
	SLOT_OCCUPIED, //ho;ding a love flow
	SLOT_DELETED // evicted flow
}slot_state_t;

typedef struct{
	slot_state_t state;
	flow_t flow;
}slot_t;

typedef struct{
	uint32_t src_ip;
	uint16_t ports[128];
	int count;
}scan_tracker_t;

static uint64_t tcp_bytes = 0;
static uint64_t udp_bytes = 0;
static uint64_t dns_bytes = 0;
static uint64_t https_bytes = 0;

static scan_tracker_t scanners[64];
static int scanner_count  = 0;

static slot_t table[TABLE_SIZE];
static int flow_count = 0;

static uint32_t hash_flow(const flow_t *f){
	uint32_t h = FNV_OFFSET;
	const uint8_t *p;

	p = (const uint8_t *)&f->src_ip;
	for(int i = 0; i < 4; i++){ h ^= p[i]; h *= FNV_PRIME;} // src_ip

	p = (const uint8_t *)&f->dst_ip;
	for(int i = 0; i < 4; i++){ h ^= p[i]; h *= FNV_PRIME;} // dst_ip

	p = (const uint8_t *)&f->src_port;
	for(int i = 0; i < 2; i++){ h ^= p[i]; h *= FNV_PRIME;} // src_port

	p = (const uint8_t *)&f->dst_port;
	for(int i = 0; i < 2; i++){ h ^= p[i]; h *= FNV_PRIME;} // dst_port

	h ^= f->protocol;
	h *= FNV_PRIME;

	return h;
}

static slot_t *ht_find(const flow_t *key){
	uint32_t idx = hash_flow(key) & TABLE_MASK;

	for(int i = 0; i < TABLE_SIZE; i++){
		slot_t *slot = &table[(idx+i) & TABLE_MASK];

		if(slot->state == SLOT_EMPTY)
			return NULL;

		if(slot->state == SLOT_OCCUPIED &&
			slot->flow.src_ip   == key->src_ip &&
			slot->flow.dst_ip   == key->dst_ip &&
			slot->flow.src_port == key->src_port &&
			slot->flow.dst_port == key->dst_port &&
			slot->flow.protocol == key->protocol)
			return slot;
	}
	return NULL;
}

static slot_t *ht_insert(const flow_t *key){

	if(flow_count >= TABLE_SIZE * 0.7){
		fprintf(stderr, "flow table over 70%% capacity\n");
		return NULL;
	}

	uint32_t idx = hash_flow(key) & TABLE_MASK;
	slot_t *tombstone = NULL;


	for(int i = 0; i<TABLE_SIZE; i++){
		slot_t *slot = 	&table[(idx+i) & TABLE_MASK];	

		if(slot->state == SLOT_EMPTY){
			slot_t *target = tombstone? tombstone : slot;
			target->state = SLOT_OCCUPIED;
			target->flow = *key;
			target->flow.first_seen = 0;   // optional safety
			target->flow.last_seen = 0;
			target->flow.packet_count = 0;
			target->flow.byte_count = 0;
			flow_count++;
			return target;
		}
	if(slot->state == SLOT_DELETED && tombstone == NULL)
		tombstone = slot;
	}
	return NULL;
}

static void *ht_delete(slot_t *slot){
	slot->state = SLOT_DELETED;
	flow_count--;
}


void normalize_flow(flow_t *f)
{
    if (f->src_ip > f->dst_ip ||
       (f->src_ip == f->dst_ip && f->src_port > f->dst_port)) {

       	uint32_t tmp_ip = f->src_ip;
        f->src_ip = f->dst_ip;
        f->dst_ip = tmp_ip;

        uint16_t tmp_port = f->src_port;
        f->src_port = f->dst_port;
        f->dst_port = tmp_port;
    }
}



void expire_flows(){
	time_t now = time(NULL);
	for(int i = 0; i < TABLE_SIZE; i++){
		if(table[i].state != SLOT_OCCUPIED)
			continue;
		if(now-table[i].flow.last_seen > FLOW_TIMEOUT)
			ht_delete(&table[i]);
	}
}

const char* classify_protocol(uint8_t proto, uint16_t sport, uint16_t dport)
{
    uint16_t port = sport < dport ? sport : dport;

    if (proto == IPPROTO_TCP) {
        if (port == 80) return "HTTP";
        if (port == 443) return "HTTPS";
    }

    if (proto == IPPROTO_UDP) {
        if (port == 53) return "DNS";
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
    else                          snprintf(buf, len, "%lu B",   bytes);
}

static void format_duration(time_t first_seen, time_t last_seen, char *buf, size_t len)
{
    time_t diff = last_seen - first_seen;
    if(diff < 0) diff = 0;	
    int h = diff / 3600;
    int m = (diff % 3600) / 60;
    int s = diff % 60;
    snprintf(buf, len, "%02d:%02d:%02d", h, m, s);
}

static int cmp_bytes(const void *a, const void *b){
	const flow_t *fa = (const flow_t *)a;
	const flow_t *fb = (const flow_t *)b;

	if(fb->byte_count > fa->byte_count)
		return 1;
	if(fb->byte_count < fa->byte_count)
		return -1;
	return 0;
}

void detect_scan(flow_t *f){
	for(int 	i = 0; i < scanner_count; i++){
		if(scanners[i].src_ip == f->src_ip){
			for(int j = 0; j < scanners[i].count; j++)
				if(scanners[i].ports[j] == f->dst_port)
					return;

			scanners[i].ports[scanners[i].count++] = f->dst_port;

			if(scanners[i].count > 20){
				struct in_addr addr;
				addr.s_addr = f -> src_ip;

				printf("PORT SCAN DETECTED FROM %s\n", inet_ntoa(addr));
			}
		return;
		}

	}
	scanners[scanner_count].src_ip = f->src_ip;
	scanners[scanner_count].ports[0] = f->dst_port;
	scanners[scanner_count].count = 1;
	scanner_count++;
}

void update_flow(flow_t *f, uint32_t packet_size)
{
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

    if(f->protocol == IPPROTO_TCP)
    	tcp_bytes += packet_size;
    if(f->protocol == IPPROTO_UDP)
    	udp_bytes += packet_size;
    if(f->protocol == IPPROTO_UDP && f->src_port == 53 || f->dst_port == 53)
    	dns_bytes += packet_size;
    if(f->src_port == 443 || f->dst_port == 443)
    	https_bytes += packet_size;

    slot->flow.packet_count++;
    slot->flow.byte_count += packet_size;
    detect_scan(&slot->flow);
}

void print_flows(void)
{
    printf("\033[H\033[J");

    uint64_t total = tcp_bytes + udp_bytes;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("==== NETMON | flows: %d | %02d:%02d:%02d ====\n\n",
           flow_count, t->tm_hour, t->tm_min, t->tm_sec);

    // collect occupied flows into a temp array for sorting
    flow_t sorted[TABLE_SIZE];
    int count = 0;
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (table[i].state == SLOT_OCCUPIED)
            sorted[count++] = table[i].flow;
    }
    qsort(sorted, count, sizeof(flow_t), cmp_bytes);

	if (total > 0) {
	    printf("\nProtocol Breakdown:\n");
	    printf("  TCP:   %.2f%%\n", (tcp_bytes * 100.0) / total);
	    printf("  UDP:   %.2f%%\n", (udp_bytes * 100.0) / total);
	    printf("  DNS:   %.2f%%\n", (dns_bytes * 100.0) / total);
	    printf("  HTTPS: %.2f%%\n", (https_bytes * 100.0) / total);
	}	

    printf("  SRC                   DST                    PROTO  PACKETS    BYTES        DURATION   BPS        PPS\n");

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    char src_buf[32], dst_buf[32], bytes_buf[16], dur_buf[16];

    for (int i = 0; i < count; i++) {
        flow_t *f = &sorted[i];
        inet_ntop(AF_INET, &f->src_ip, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &f->dst_ip, dst, INET_ADDRSTRLEN);
        snprintf(src_buf, sizeof(src_buf), "%s:%d", src, f->src_port);
        snprintf(dst_buf, sizeof(dst_buf), "%s:%d", dst, f->dst_port);
        format_bytes(f->byte_count, bytes_buf, sizeof(bytes_buf));
        format_duration(f->first_seen, f->last_seen, dur_buf, sizeof(dur_buf));

        double duration = difftime(f->last_seen, f->first_seen);
		if (duration <= 0) duration = 1;   // avoid divide-by-zero

		double bps = (f->byte_count * 8.0) / duration;
		double pps = f->packet_count / duration;


        printf("  %-22s %-22s %-6s %-10lu %-12s %-10s %-10.0f %-10.2f\n",
       	src_buf, dst_buf, classify_protocol(f->protocol, f->src_port, f->dst_port),
       	f->packet_count,
       	bytes_buf,
       	dur_buf,
       	bps,
       	pps);
    }
}