#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int packetinject(pcap_t *pcd, const u_char *packet, int opt, char *message);
int tcp_forward_inject(pcap_t *pcd, const u_char *packet, char *message);
int tcp_backward_inject(pcap_t *pcd, const u_char *packet, char *message, int opt);
int http302(pcap_t *pcd, const u_char *packet, char *message);
int makehttp302(char *message, char *addr);
int makeip_checksum(struct ip * iph);
int maketcp_checksum(struct ip* iph, struct tcphdr * tcph, char *message);
void SWAP(u_char *src, u_char *dst, int len);