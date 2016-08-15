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
char HTTP1_1[] = {0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a};

int packetinject(pcap_t *pcd, const u_char *packet, int opt, char *message){
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
            if(opt == 1)
                return tcp_forward_inject(pcd, packet, message);
            if(opt == 2)
                return tcp_backward_inject(pcd, packet, message);
        }
    }
    return 0;
}

int tcp_forward_inject(pcap_t *pcd, const u_char *packet, char *message){
    struct ether_header *etheh;
    struct ip* iph;
    struct tcphdr *tcph;
    u_char *cp = packet;

    etheh = (struct ether_header*)cp;
    cp += sizeof(struct ether_header);
    iph = (struct ip*)cp;
    cp += sizeof(struct ip);
    tcph = (struct tcphdr*)cp;
    cp += sizeof(struct tcphdr);

    if(!memcmp(HTTP1_1, cp, sizeof(HTTP1_1))){
        tcph->seq = htonl(ntohl(tcph->seq) + ntohs(iph->ip_len) - tcph->th_off*4 - iph->ip_hl*4);
        iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
        tcph->psh = 0;
        tcph->fin = 1;
        iph->ip_tos = 0x44;

        memcpy(cp, message, strlen(message));
        makeip_checksum(iph);
        maketcp_checksum(iph, tcph, message);
        return pcap_inject(pcd, packet, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
    }
}

int tcp_backward_inject(pcap_t *pcd, const u_char *packet, char *message){
    struct ether_header *etheh;
    struct ip* iph;
    struct tcphdr *tcph;
    u_char *cp = packet;

    etheh = (struct ether_header*)cp;
    cp += sizeof(struct ether_header);
    iph = (struct ip*)cp;
    cp += sizeof(struct ip);
    tcph = (struct tcphdr*)cp;
    cp += sizeof(struct tcphdr);

    if(!memcmp(HTTP1_1, cp, sizeof(HTTP1_1))){
        struct ether_header eht;
        struct ip ipht;
        struct tcphdr tcpht;
        memcpy(&eht, etheh, sizeof(struct ether_header));
        memcpy(&ipht, iph, sizeof(struct ip));
        memcpy(&tcpht, tcph, sizeof(struct tcphdr));

        memcpy(etheh->ether_dhost, eht.ether_shost, sizeof(eht.ether_shost));
        memcpy(etheh->ether_shost, eht.ether_dhost, sizeof(eht.ether_dhost));
        iph->ip_dst = ipht.ip_src;
        iph->ip_src = ipht.ip_dst;
        tcph->th_dport = tcpht.th_sport;
        tcph->th_sport = tcpht.th_dport;

        tcph->seq = tcpht.ack_seq;
        tcph->ack_seq = htonl(ntohl(tcpht.seq) + ntohs(ipht.ip_len) - tcpht.th_off*4 - ipht.ip_hl*4);

        iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
        tcph->fin = 1;

        memcpy(cp, message, strlen(message));
        makeip_checksum(iph);
        maketcp_checksum(iph, tcph, message);
        return pcap_inject(pcd, packet, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
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

int maketcp_checksum(struct ip* iph, struct tcphdr * tcph, char *message){
    struct pseudo_header ph;
    u_short *checksum = &ph;
    u_short sum;
    u_int cs = 0;
    tcph->th_sum = 0;
    ph.dip = iph->ip_dst.s_addr;
    ph.sip = iph->ip_src.s_addr;
    ph.reserved = 0;
    ph.proto = iph->ip_p;
    ph.len = iph->ip_len - ntohs(sizeof(struct ip));

    for(int i=0; i<6; i++)
        cs += (u_int)checksum[i];

    checksum = tcph;
    for(int i=0; i<tcph->th_off*4; i++)
        cs += (u_int)checksum[i];

    checksum = message;
    for(int i=0; i<strlen(message)/2; i++){
        cs += (u_int)checksum[i];
    }
    if(strlen(message)%2)
        cs += (u_int)message[strlen(message)-1];

    cs = (cs >> 16) + (cs & 0xffff);
    cs += cs >> 16;

    sum = (~cs)&0xffff;
    return tcph->th_sum = sum;
}
