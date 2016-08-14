#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "pkcntl.h"

int packetinject(pcap_t *pcd, u_char *packet){
    if(packet == NULL)
        return 0;

    struct ether_header *etheh;
    u_char *cp = packet;
    etheh = (struct ether_header*)cp;
    cp += sizeof(struct ether_header);

    if(etheh->ether_type == htons(ETHERTYPE_IP)){
        struct ip *iph;
        iph = (struct ip*)cp;
        if(iph->ip_p == IPPROTO_TCP){
            return tcp_inject(pcd, packet);
        }
    }
    return 0;
}

int tcp_inject(pcap_t *pcd, u_char *packet){
    struct ether_header * etheh;
    struct ip* iph;
    struct tcphdr *tcph;
    u_char *cp = packet;
    u_char *data = "blocked";

    char HTTP1_1[] = {0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a};

    etheh = (struct ether_header*)cp;
    cp += sizeof(struct ether_header);
    iph = (struct ip*)cp;
    cp += sizeof(struct ip);
    tcph = (struct tcphdr*)cp;
    cp += sizeof(struct tcphdr);

    if(!memcmp(HTTP1_1, cp, sizeof(HTTP1_1))){
        makeip_checksum(iph);
        tcph->syn += ntohs(iph->ip_len) + ntohs(tcph->th_off)*4;
        tcph->fin = 1;
        memcpy(cp, data, sizeof(data));
        return pcap_inject(pcd, packet, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(data));
    }
}

int makeip_checksum(struct ip * iph){
    u_short *checksum = iph;
    u_short sum;
    u_int cs = 0;
    iph->ip_sum = 0;
    for(int i=0; i<iph->ip_hl*2; i++)
        cs += (u_int)checksum[i];
    cs = (cs >> 16) + (cs & 0xffff);
    cs += cs >> 16;

    sum = (~cs)&0xffff;
    return iph->ip_sum = sum;
}

int maketcp_checksum(struct ip* iph, struct tcphdr * tcph){

}
