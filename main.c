#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcntl.h"


int main(){
	pcap_if_t *alldevs;
	pcap_if_t *d;
	struct pcap_pkthdr hdr;
	const u_char *packet;
	char message[1460];
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next){
		if (d->description)
			printf("%d. (%s)\n", ++i, d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0){
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i){
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, NULL, NULL, errbuf)) == NULL){
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs);
	int opt;
	printf("1. forward\n");
	printf("2. backward\n");
	printf("3. http302 redirection\n");
	printf("? ");
	scanf("%d", &opt);
	if (opt == 1 || opt == 2)
		printf("message? ");
	else if (opt == 3){
		printf("site? ");
	}
	fflush(stdin);
	if (opt == 1 || opt == 2)
		gets(message);
	else if (opt == 3){
		char temp[64];
		gets(temp);
		makehttp302(message, temp);
	}
	while (1) {
		packet = (u_char*)pcap_next(adhandle, &hdr);
		packetinject(adhandle, packet, opt, message);
	}
	return 0;
}
