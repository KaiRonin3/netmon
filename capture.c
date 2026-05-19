#include "flow.h"
#include "parser.h"
#include "analysis.h"
#include <pcap.h>
#include <stdio.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>
#include <time.h>

static pcap_t      *handle;
static atomic_int   expire_flag = 0;

static void sig_alarm(int sig)
{
    (void)sig;
    expire_flag = 1;
}

static void sig_handler(int sig)
{
    (void)sig;
    pcap_breakloop(handle);
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data)
{
    (void)param;
    if (expire_flag) {
        expire_flows();
        expire_flag = 0;
        alarm(FLOW_TIMEOUT);
    }
    parse_packet(header, pkt_data);
}

int start_capture(const char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    analysis_init();   /* register all anomaly detectors */

    signal(SIGINT,  sig_handler);
    signal(SIGALRM, sig_alarm);
    alarm(FLOW_TIMEOUT);

    pcap_loop(handle, 0, packet_handler, NULL);

    print_flows();     /* final snapshot on exit */
    pcap_close(handle);

    /* Export flow table to CSV on exit */
    char csv_path[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(csv_path, sizeof(csv_path), "netmon_%Y%m%d_%H%M%S.csv", t);
    export_flows_csv(csv_path);

    return 0;
}