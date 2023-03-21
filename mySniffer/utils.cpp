# include "utils.h"


/* 解析链路层 */
int parsing_fram(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	MAC_HEADER* mach = (MAC_HEADER*)pkt;

	data->mach = (MAC_HEADER*)malloc(sizeof(MAC_HEADER));
	if (NULL == data->mach) {
		return -1;
	}

	// 复制信息
	for (int i = 0; i < 6; i++) {
		data->mach->src[i] = mach->src[i];
		data->mach->dest[i] = mach->dest[i];
	}
	data->mach->type = ntohs(mach->type);

	npkt->n_sum++;
	// 解析上层报文
	switch (data->mach->type)
	{
	case 0x0806:
		break;
	case 0x0800:
		break;
	case 0x86dd:
		break;
	default:
		npkt->n_other++;
		return -1;
		break;
	}
	return 1;
}


/* 解析网络层 ARP */
int parsing_arp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	ARP_HEADER* arph = (ARP_HEADER*)pkt;
	
	data->arph = (ARP_HEADER*)malloc(sizeof(ARP_HEADER));
	if (NULL == data->arph) {
		return -1;
	}

	// 复制信息
	for (int i = 0; i < 6; i++) {
		data->arph->srcMAC[i] = arph->srcMAC[i];
		data->arph->destMAC[i] = arph->destMAC[i];
		if (i < 4) {
			data->arph->srcIP[i] = arph->srcIP[i];
			data->arph->destIP[i] = arph->destIP[i];
		}
	}
	data->arph->hrdLen = arph->hrdLen;
	data->arph->proLen = arph->proLen;
	data->arph->hrdType = ntohs(arph->hrdType);
	data->arph->proType = ntohs(arph->proType);
	data->arph->op = ntohs(arph->op);

	strcpy(data->pktType, "ARP");
	npkt->n_arp++;
	return 1;
}


/* 解析网络层 IP */
int parsing_ip(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	IP_HEADER* iph = (IP_HEADER*)pkt;

	data->iph = (IP_HEADER*)malloc(sizeof(IP_HEADER));
	if (NULL == data->iph) {
		return -1;
	}

	// 复制信息
	data->iph->hdrLen = iph->hdrLen;
	data->iph->version = iph->version;
	data->iph->tos = iph->tos;
	data->iph->id = iph->id;
	data->iph->flag_off = iph->flag_off;
	data->iph->ttl = iph->ttl;
	data->iph->proto = iph->proto;
	data->iph->check = iph->check;
	data->iph->srcIP = iph->srcIP;
	data->iph->destIP = iph->destIP;
	data->iph->option = iph->option;
	data->iph->tLen = ntohs(iph->tLen);

	npkt->n_ip++;
	// 解析上层协议
	int len = iph->hdrLen * 4;
	switch (iph->proto)
	{
	case PROTO_ICMP:

		break;
	case PROTO_TCP:

		break;
	case PROTO_UDP:

		break;
	default:
		return -1;
		break;
	}
	return 1;
}


/* 解析网络层 IPv6 */
int parsing_ipv6(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	IP6_HEADER* ip6h = (IP6_HEADER*)pkt;

	data->ip6h = (IP6_HEADER*)malloc(sizeof(IP6_HEADER));
	if (NULL == data->ip6h) {
		return -1;
	}

	// 复制信息
	for (int i = 0; i < 16; i++) {
		data->ip6h->srcAddr[i] = ip6h->srcAddr[i];
		data->ip6h->destAddr[i] = ip6h->destAddr[i];
	}
	data->ip6h->version = ip6h->version;
	data->ip6h->flowType = ip6h->flowType;
	data->ip6h->flowLabel = ip6h->flowLabel;
	data->ip6h->nh = ip6h->nh;
	data->ip6h->hlim = ip6h->hlim;
	data->ip6h->plen = ntohs(ip6h->plen);

	npkt->n_ip6++;
	// 解析上层协议
	switch (ip6h->nh)
	{
	case 0x3a:
		break;
	case 0x06:
		break;
	case 0x11:
		break;
	default:
		return -1;
		break;
	}
	return 1;
}


/* 解析传输层 ICMP */
int parsing_icmp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	ICMP_HEADER* icmph = (ICMP_HEADER*)pkt;

	data->icmph = (ICMP_HEADER*)malloc(sizeof(ICMP_HEADER));
	if (NULL == data->icmph) {
		return -1;
	}

	// 复制信息
	data->icmph->type = icmph->type;
	data->icmph->code = icmph->code;
	data->icmph->seq = icmph->seq;
	data->icmph->check = icmph->check;

	strcpy(data->pktType, "ICMP");
	npkt->n_icmp++;
	return 1;
}


/* 解析传输层 ICMP6 */
int parsing_icmp6(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	ICMP6_HEADER* icmp6h = (ICMP6_HEADER*)pkt;

	data->icmp6h = (ICMP6_HEADER*)malloc(sizeof(ICMP6_HEADER));
	if (NULL == data->icmp6h) {
		return -1;
	}

	// 复制信息
	for (int i = 0; i < 6; i++) {
		data->icmp6h->op_ethaddr[i] = icmp6h->op_ethaddr[i];
	}
	data->icmp6h->type = icmp6h->type;
	data->icmp6h->code = icmp6h->code;
	data->icmp6h->seq = icmp6h->seq;
	data->icmp6h->chksum = icmp6h->chksum;
	data->icmp6h->op_type = icmp6h->op_type;
	data->icmp6h->op_len = icmp6h->op_len;

	strcpy(data->pktType, "ICMPv6");
	npkt->n_icmp6++;
	return 1;
}


/* 解析传输层 TCP */
int parsing_tcp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	TCP_HEADER* tcph = (TCP_HEADER*)pkt;

	data->tcph = (TCP_HEADER*)malloc(sizeof(TCP_HEADER));
	if (NULL == data->tcph) {
		return -1;
	}

	// 复制信息
	data->tcph->srcPort = ntohs(tcph->srcPort);
	data->tcph->destPort = ntohs(tcph->destPort);
	data->tcph->seq = tcph->seq;
	data->tcph->ack_seq = tcph->ack_seq;
	data->tcph->res1 = tcph->res1;
	data->tcph->doff = tcph->doff;
	data->tcph->fin = tcph->fin;
	data->tcph->syn = tcph->syn;
	data->tcph->rst = tcph->rst;
	data->tcph->psh = tcph->psh;
	data->tcph->ack = tcph->ack;
	data->tcph->urg = tcph->urg;
	data->tcph->ece = tcph->ece;
	data->tcph->cwr = tcph->cwr;
	data->tcph->window = tcph->window;
	data->tcph->check = tcph->check;
	data->tcph->urgPtr = tcph->urgPtr;
	data->tcph->option = tcph->option;

	// http分支
	if (ntohs(tcph->destPort) == 80 || ntohs(tcph->srcPort) == 80) {
		strcpy(data->pktType, "HTTP");
		npkt->n_http++;
	}
	else
	{
		strcpy(data->pktType, "TCP");
		npkt->n_tcp++;
	}
	return 1;
}


/* 分析传输层 UDP */
int parsing_udp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	UDP_HEADER* udph = (UDP_HEADER*)pkt;

	data->udph = (UDP_HEADER*)malloc(sizeof(UDP_HEADER));
	if (NULL == data->udph) {
		return -1;
	}

	// 复制数据
	data->udph->srcPort = ntohs(udph->srcPort);
	data->udph->destPort = ntohs(udph->destPort);
	data->udph->len = ntohs(udph->len);
	data->udph->check = udph->check;

	strcpy(data->pktType, "UDP");
	npkt->n_udp++;
	return 1;
}