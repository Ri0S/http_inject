#ifndef PKCNTL_H
#define PKCNTL_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct pseudo_header{
    u_int sip;
    u_int dip;
    u_char reserved;
    u_char proto;
    u_short len;
};

int packetinject(pcap_t *pcd, const u_char *packet, int opt, char *message);
int tcp_forward_inject(pcap_t *pcd, const u_char *packet, char *message);
int tcp_backward_inject(pcap_t *pcd, const u_char *packet, char *message);
int makeip_checksum(struct ip * iph);
int maketcp_checksum(struct ip* iph, struct tcphdr * tcph, char *message);

#endif // PKCNTL_H

