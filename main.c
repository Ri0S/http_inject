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
    char message[1460] = {0};
    int opt;

    pcap_t *pcd;  // packet capture descriptor

    printf("1. forward\n");
    printf("2. backward\n");
    printf("3. http302 redirection\n");
    printf("? ");
    fflush(stdout);
    scanf("%d", &opt);
    if(opt == 1 || opt == 2)
        printf("message? ");
    else if(opt == 3){
        printf("site? ");
    }
    fflush(stdout);
    gets(message);
    if(opt == 1 || opt == 2)
        gets(message);
    else if(opt == 3){
        char temp[64];
        gets(temp);

    }

    dev = pcap_lookupdev(errbuf); // 디바이스 이름
    if (dev == NULL)    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcd = pcap_open_live(dev, BUFSIZ,  1, 1, errbuf);
    if (pcd == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }

    while(1){
        packet = pcap_next(pcd, &hdr);
        packetinject(pcd, packet, opt, message);
    }
    return 0;
}

