# include "utils.h"


/* 解析链路层 */
int parsing_fram(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	MAC_HEADER* mach = (MAC_HEADER*)pkt;
	if (NULL == mach) {
		return -1;
	}

	data->mach = (MAC_HEADER*)malloc(sizeof(MAC_HEADER));
	if (NULL == data->mach) {
		return -1;
	}

	// 复制信息
	for (int i = 0; i < 6; i++) {
		data->mach->dest[i] = mach->dest[i];
		data->mach->src[i] = mach->src[i];
	}
	data->mach->type = ntohs(mach->type);

	npkt->n_sum++;
	// 解析上层报文
	switch (data->mach->type)
	{
	case 0x0806:
		return parsing_arp((uchar*)pkt + 14, data, npkt);
		break;
	case 0x0800:
		return parsing_ip((uchar*)pkt + 14, data, npkt);
		break;
	case 0x86dd:
		return parsing_ip6((uchar*)pkt + 14, data, npkt);
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
	data->iph->tLen = ntohs(iph->tLen);
	data->iph->id = ntohs(iph->id);
	//data->iph->flag_off = ntohs(iph->flag_off);
	data->iph->flag = iph->flag;
	data->iph->off1 = iph->off1;
	data->iph->off2 = iph->off2;
	data->iph->ttl = iph->ttl;
	data->iph->proto = iph->proto;
	data->iph->check = ntohs(iph->check);
	data->iph->srcIP = iph->srcIP;
	data->iph->destIP = iph->destIP;
	data->iph->option = ntohs(iph->option);

	npkt->n_ip++;
	// 解析上层协议
	int len = iph->hdrLen * 4;
	switch (data->iph->proto)
	{
	case PROTO_ICMP:
		return parsing_icmp((uchar*)iph + len, data, npkt);
		break;
	case PROTO_TCP:
		return parsing_tcp((uchar*)iph + len, data, npkt);
		break;
	case PROTO_UDP:
		return parsing_udp((uchar*)iph + len, data, npkt);
		break;
	default:
		return -1;
		break;
	}
	return 1;
}


/* 解析网络层 IPv6 */
int parsing_ip6(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt) {
	IP6_HEADER* ip6h = (IP6_HEADER*)pkt;

	data->ip6h = (IP6_HEADER*)malloc(sizeof(IP6_HEADER));
	if (NULL == data->ip6h) {
		return -1;
	}

	// 复制信息
	data->ip6h->version = ip6h->version;
	data->ip6h->flowType1 = ip6h->flowType1;
	data->ip6h->flowType2 = ip6h->flowType2;
	data->ip6h->flowLabel1 = ip6h->flowLabel1;
	data->ip6h->flowLabel2 = ntohs(ip6h->flowLabel2);

	data->ip6h->plen = ntohs(ip6h->plen);
	data->ip6h->nh = ip6h->nh;
	data->ip6h->hlim = ip6h->hlim;
	for (int i = 0; i < 8; i++) {
		data->ip6h->srcAddr[i] = ntohs(ip6h->srcAddr[i]);
		data->ip6h->destAddr[i] = ntohs(ip6h->destAddr[i]);
	}

	npkt->n_ip6++;
	// 解析上层协议
	switch (data->ip6h->nh)
	{
	case 0x3a:
		return parsing_icmp6((uchar*)ip6h + 40, data, npkt);
		break;
	case 0x06:
		return parsing_tcp((uchar*)ip6h + 40, data, npkt);
		break;
	case 0x11:
		return parsing_udp((uchar*)ip6h + 40, data, npkt);
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
	data->icmp6h->type = icmp6h->type;
	data->icmp6h->code = icmp6h->code;
	data->icmp6h->chksum = icmp6h->chksum;

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
	data->tcph->seq = ntohl(tcph->seq);
	data->tcph->ack_seq = ntohl(tcph->ack_seq);
	data->tcph->res1 = tcph->res1;
	data->tcph->doff = tcph->doff;
	data->tcph->fin = tcph->fin;
	data->tcph->syn = tcph->syn;
	data->tcph->rst = tcph->rst;
	data->tcph->psh = tcph->psh;
	data->tcph->ack = tcph->ack;
	data->tcph->urg = tcph->urg;
	data->tcph->res2 = tcph->res2;
	data->tcph->window = ntohs(tcph->window);
	data->tcph->check = ntohs(tcph->check);
	data->tcph->urgPtr = ntohs(tcph->urgPtr);
	data->tcph->option = ntohs(tcph->option);

	npkt->n_tcp++;
	// http分支
	if (ntohs(tcph->destPort) == 80 || ntohs(tcph->srcPort) == 80) {
		strcpy(data->pktType, "HTTP");
		npkt->n_http++;
	}
	else if (data->tcph->destPort == 443 || data->tcph->srcPort == 443) {
		strcpy(data->pktType, "TLS");
	}
	else
	{
		strcpy(data->pktType, "TCP");
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
	data->udph->check = ntohs(udph->check);

	strcpy(data->pktType, "UDP");
	npkt->n_udp++;
	return 1;
}