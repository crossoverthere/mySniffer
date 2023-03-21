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
