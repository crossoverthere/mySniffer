#pragma once
/***********************************************
* 协议报文数据结构
* 自定义数据结构
* 网络数据多字节按照大端模式. 需要转换
* 结构体位域从低位开始赋值,故声明顺序需要置反
************************************************/

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321


// MAC帧头 14字节
typedef struct machdr {
	unsigned char dest[6];		// 目的MAC地址
	unsigned char src[6];		// 源MAC地址
	unsigned short type;		// 帧类型
}MAC_HEADER;


// ARP报文 28字节
typedef struct arphdr {
	/* ARP报头 */
	unsigned short hrdType;		// 硬件类型
	unsigned short proType;		// 上层协议类型
	unsigned char hrdLen;		// MAC地址长度
	unsigned char proLen;		// 协议地址长度
	unsigned short op;			// 操作码

	unsigned char srcMAC[6];	// 源MAC地址
	unsigned char srcIP[4];		// 源IP地址
	unsigned char destMAC[6];	// 目的MAC地址
	unsigned char destIP[4];	// 目的IP地址

}ARP_HEADER;


// IP报头 24字节
typedef struct iphdr {
#if defined(LITTLE_ENDIAN)
	unsigned char hdrLen : 4;	// 4位首部长度
	unsigned char version : 4;	// 4位版本
#elif defined(BIG_ENDIAN)
	unsigned char version : 4;
	unsigned char hdrLen : 4;
#endif

	unsigned char tos;			// tos服务类型
	unsigned short tLen;		// 总长度
	unsigned short id;			// 
	//unsigned short flag_off;	// 标志与片偏移
	unsigned char off1 : 5;		// 片偏移高5位
	unsigned char flag : 3;		// 标志位
	unsigned char off2;			// 片偏移低8位


	unsigned char ttl;			// TTL
	unsigned char proto;		// 协议
	unsigned short check;		// 首部校验和
	unsigned int srcIP;			// 源IP地址
	unsigned int destIP;		// 目的IP地址
	unsigned int option;		// 选项
}IP_HEADER;


// TCP报头
typedef struct tcphdr {
	unsigned short srcPort;		// 源端口地址
	unsigned short destPort;	// 目的端口地址
	unsigned int seq;			// 序号
	unsigned int ack_seq;		// 确认号
	
#if defined(LITTLE_ENDIAN)
	unsigned short res1 : 4;
	unsigned short doff : 4;
	unsigned short fin : 1;
	unsigned short syn : 1;
	unsigned short rst : 1;
	unsigned short psh : 1;
	unsigned short ack : 1;
	unsigned short urg : 1;
	unsigned short res2 : 2;
#elif defined(BIG_ENDIAN)
	unsigned short doff : 4;
	unsigned short res1 : 4;
	unsigned short res2 : 2;
	unsigned short urg : 1;
	unsigned short ack : 1;
	unsigned short psh : 1;
	unsigned short rst : 1;
	unsigned short syn : 1;
	unsigned short fin : 1;
#endif


	unsigned short window;		// 窗口大小
	unsigned short check;		// 校验和
	unsigned short urgPtr;		// 紧急指针
	unsigned int option;		// 选项
}TCP_HEADER;


// UDP报头 8字节
typedef struct udphdr {
	unsigned short srcPort;		// 源端口
	unsigned short destPort;	// 目的端口
	unsigned short len;			// 总长度
	unsigned short check;		// 校验和
}UDP_HEADER;


// ICMP报文
typedef struct icmphdr {
	unsigned char type;			// 类型
	unsigned char code;			// 代码
	unsigned short check;		// 校验和
}ICMP_HEADER;


// IPv6
typedef struct ip6hdr {
	//unsigned int version : 4;		// 版本
	//unsigned int flowType : 8;	// 流类型
	//unsigned int flowLabel : 20;	// 流标签

	unsigned char flowType1 : 4;	// 流类型高4位
	unsigned char version : 4;		// 版本
	unsigned char flowLabel1 : 4;	// 流标签高4位
	unsigned char flowType2 : 4;	// 流类型低4位
	unsigned short flowLabel2 : 16;	// 流标签低16位


	unsigned short plen;		// 有效载荷长度
	unsigned char nh;			// 下一个报头
	unsigned char hlim;			// 跳跃限制
	unsigned short srcAddr[8];	// 源地址
	unsigned short destAddr[8];	// 目的地址
}IP6_HEADER;


// ICMPv6
typedef struct icmp6hdr {
	unsigned char type;			// 类型
	unsigned char code;			// 代码
	unsigned short chksum;		// 校验和
}ICMP6_HEADER;


// 包统计
struct PKTCOUNT {
	int n_ip;
	int n_ip6;
	int n_arp;
	int n_tcp;
	int n_udp;
	int n_icmp;
	int n_icmp6;
	int n_http;
	//int n_https;
	int n_other;
	int n_sum ;

	PKTCOUNT() {
		memset(this, 0, sizeof(PKTCOUNT));
	}
};


// 抓包信息
struct PKTDATA{
	char pktType[8];			// 包类型
	int time[6];				// 时间
	int len;					// 长度
	unsigned char* pktData;

	MAC_HEADER* mach;			// MAC帧头
	ARP_HEADER* arph;			// ARP报头

	IP_HEADER* iph;				// IP报头
	IP6_HEADER* ip6h;			// IPv6报头

	ICMP_HEADER* icmph;			// ICMP报头
	ICMP6_HEADER* icmp6h;		// ICMPv6报头

	TCP_HEADER* tcph;			// TCP报头
	UDP_HEADER* udph;			// UDP报头

	//void* apph;					//应用层报头


	void freePtr() {
		free(pktData);
		free(mach);
		free(arph);
		free(iph);
		free(ip6h);
		free(icmph);
		free(icmp6h);
		free(tcph);
		free(udph);
	//	free(apph);
	}
};