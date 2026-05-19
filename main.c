#include <pcap.h>
#include <stdio.h>

int start_capture(const char *dev);

int main(int argc, char *argv[]){
	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE], *dev;
	int i = 0, inum;


	if(argc >= 2){
		dev = argv[1];
	}
	else{
		if(pcap_findalldevs(&alldevs, errbuf) == -1){
			fprintf(stderr, "Error: %s\n", errbuf);
			return 1;
		}
		for(d=alldevs; d; d=d->next)
			printf("%d. %s\n", ++i, d->name);

		printf("select an interface ");
		scanf("%d", &inum);

		for(d=alldevs, i=0; i<inum-1; d=d->next, i++);
		dev = d->name;

	}
	pcap_freealldevs(alldevs);
	return start_capture(dev);
}