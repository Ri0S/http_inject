#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "pkcntl.h"
int main(void)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr hdr;
    const u_char *packet;
    pcap_t *pcd;  // packet capture descriptor

    dev = pcap_lookupdev(errbuf); // 디바이스 이름
    if (dev == NULL)    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcd = pcap_open_live(dev, BUFSIZ,  0, 1, errbuf);
    if (pcd == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    while(1){
        packet = pcap_next(pcd, &hdr);
        packetinject(pcd, packet);
    }
    return 0;
}

