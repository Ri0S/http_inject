#ifndef PKCNTL_H
#define PKCNTL_H

#include <pcap.h>

int packetinject(pcap_t *pcd, u_char *packet);
int tcp_inject(pcap_t *pcd, u_char *packet);

#endif // PKCNTL_H

