#include <pcap.h>
#include <stdio.h>
#include <string.h>

int start_capture(const char *dev);

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;

    if (argc >= 2) {
        ret = start_capture(argv[1]);
    } else {
        pcap_if_t *alldevs, *d;
        int i = 0, inum;

        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error: %s\n", errbuf);
            return 1;
        }

        for (d = alldevs; d; d = d->next)
            printf("%d. %s\n", ++i, d->name);

        printf("select an interface: ");
        if (scanf("%d", &inum) != 1 || inum < 1 || inum > i) {
            fprintf(stderr, "Invalid selection\n");
            pcap_freealldevs(alldevs);
            return 1;
        }

        /* Walk to the selected device */
        for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

        /* Copy the name before freeing the list */
        char devname[64];
        strncpy(devname, d->name, sizeof(devname) - 1);
        devname[sizeof(devname) - 1] = '\0';

        pcap_freealldevs(alldevs);   /* safe to free now — we have a copy */
        ret = start_capture(devname);
    }

    return ret;
}