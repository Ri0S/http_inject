#ifndef PKCNTL_H
#define PKCNTL_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int packetinject(pcap_t *pcd, u_char *packet);
int tcp_inject(pcap_t *pcd, u_char *packet);
int makeip_checksum(struct ip * iph);
int maketcp_checksum(struct ip* iph, struct tcphdr * tcph);

#endif // PKCNTL_H

