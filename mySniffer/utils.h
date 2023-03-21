#pragma once

/***************************
* 功能函数
* 协议解析函数
****************************/

#include<WinSock2.h>
#include "protocol.h"

#pragma comment(lib,"ws2_32.lib")
#define PROTO_ICMP 1
#define PROTO_TCP 6					
#define PROTO_UDP 17

typedef unsigned char uchar;


/* 解析链路层 */
int parsing_fram(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);
/* 解析网络层 ARP */
int parsing_arp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);
/* 解析网络层 IP */
int parsing_ip(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);
/* 解析网络层 IPv6 */
int parsing_ip6(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);
/* 解析传输层 ICMP */
int parsing_icmp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);
/* 解析传输层 ICMP6 */
int parsing_icmp6(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);
/* 解析传输层 TCP */
int parsing_tcp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);
/* 分析传输层 UDP */
int parsing_udp(const uchar* pkt, PKTDATA* data, PKTCOUNT* npkt);