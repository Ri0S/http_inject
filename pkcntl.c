#include "pkcntl.h"
#include "header.h"

int packetinject(pcap_t *pcd, const u_char *packet, int opt, char *message) {
	if (packet == NULL)
		return 0;

	struct ether_header *etheh;
	u_char *cp = (u_char*)packet;
	etheh = (struct ether_header*)cp;
	cp += sizeof(struct ether_header);

	if (etheh->ether_type == htons(ETHERTYPE_IP)) {
		struct ip *iph;
		iph = (struct ip*)cp;
		if (iph->ip_p == IPPROTO_TCP) {
			if (opt == 1)
				return tcp_forward_inject(pcd, packet, message);
			if (opt == 2)
				return tcp_backward_inject(pcd, packet, message, opt);
			if (opt == 3)
				return tcp_backward_inject(pcd, packet, message, opt);
		}
	}
	return 0;
}

int tcp_forward_inject(pcap_t *pcd, const u_char *packet, char *message) {
	struct ether_header *etheh;
	struct ip* iph;
	struct tcphdr *tcph;
	u_char *cp = (u_char*)packet;

	etheh = (struct ether_header*)cp;
	cp += sizeof(struct ether_header);
	iph = (struct ip*)cp;
	cp += sizeof(struct ip);
	tcph = (struct tcphdr*)cp;
	cp += sizeof(struct tcphdr);

	if (!memcmp(HTTP1_1, cp, sizeof(HTTP1_1))) {
		tcph->seq = htonl(ntohl(tcph->seq) + ntohs(iph->ip_len) - tcph->th_off * 4 - iph->ip_hl * 4);
		iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
		tcph->psh = 0;
		tcph->fin = 1;
		tcph->window = 0;

		memcpy(cp, message, strlen(message));
		makeip_checksum(iph);
		maketcp_checksum(iph, tcph, message);
		return pcap_sendpacket(pcd, packet, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
	}
}

int tcp_backward_inject(pcap_t *pcd, const u_char *packet, char *message, int opt) {
	struct ether_header *etheh;
	struct ip* iph;
	struct tcphdr *tcph;
	char finpck[1514];
	u_char *cp = (u_char*)packet;

	etheh = (struct ether_header*)cp;
	cp += sizeof(struct ether_header);
	iph = (struct ip*)cp;
	cp += sizeof(struct ip);
	tcph = (struct tcphdr*)cp;
	cp += sizeof(struct tcphdr);

	if (!memcmp(HTTP1_1, cp, sizeof(HTTP1_1))) {
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
		iph->ip_off = 0;

		tcph->th_dport = tcpht.th_sport;
		tcph->th_sport = tcpht.th_dport;

		tcph->seq = tcpht.ack_seq;
		tcph->ack_seq = htonl(ntohl(tcpht.seq) + ntohs(ipht.ip_len) - tcpht.th_off * 4 - ipht.ip_hl * 4);

		iph->ip_ttl = 0x80;
		iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
		if (opt==2)
			tcph->fin = 1;
		tcph->window = 0xf0fa;


		memcpy(cp, message, strlen(message));
		makeip_checksum(iph);
		maketcp_checksum(iph, tcph, message);

		return pcap_sendpacket(pcd, packet, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + strlen(message));
	}
}
int makeip_checksum(struct ip * iph) {
	u_short *checksum = (u_short*)iph;
	u_short sum;
	u_int cs = 0;
	iph->ip_sum = 0;
	for (int i = 0; i<iph->ip_hl * 2; i++)
		cs += (u_int)checksum[i];
	cs = (cs >> 16) + (cs & 0xffff);
	cs += cs >> 16;

	sum = (~cs) & 0xffff;
	return iph->ip_sum = sum;
}

int maketcp_checksum(struct ip* iph, struct tcphdr * tcph, char *message) {
	struct pseudo_header ph;
	u_short *checksum = (u_short*)&ph;
	u_short sum;
	u_int cs = 0;
	tcph->th_sum = 0;
	ph.dip = iph->ip_dst.s_addr;
	ph.sip = iph->ip_src.s_addr;
	ph.reserved = 0;
	ph.proto = iph->ip_p;
	ph.len = iph->ip_len - ntohs(sizeof(struct ip));

	for (int i = 0; i<sizeof(struct pseudo_header) / 2; i++)
		cs += (u_int)checksum[i];

	checksum = (u_short*)tcph;
	for (int i = 0; i<tcph->th_off * 2; i++)
		cs += (u_int)checksum[i];

	checksum = (u_short*)message;
	for (int i = 0; i<strlen(message) / 2; i++) {
		cs += (u_int)checksum[i];
	}
	if (strlen(message) % 2)
		cs += (u_int)message[strlen(message) - 1];

	cs = (cs >> 16) + (cs & 0xffff);
	cs += cs >> 16;

	sum = (~cs) & 0xffff;
	return tcph->th_sum = sum;
}
int makehttp302(char *message, char *addr){
	strcpy(message, "HTTP/1.1 302 Found\r\nLocation: http://");
	strcat(message, addr);
	return strcat(message, "/\r\n");
}

void SWAP(u_char *src, u_char *dst, int len){
	u_char *temp;
	temp = (u_char*)malloc(sizeof(u_char)*len);
	memcpy(temp, src, len);
	memcpy(src, dst, len);
	memcpy(dst, temp, len);
	free(temp);
}