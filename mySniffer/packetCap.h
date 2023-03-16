#pragma once
/*********************
// 实现对数据捕获
**********************/

#include <pcap.h>


class PacketCapture {
public:
	PacketCapture();
	~PacketCapture();

private:
	pcap_if_t* allDevs;			// 所有网卡设备
	pcap_if_t* pdev;
	char* errBuf;				// 错误信息

public:
	bool hasDevs();				
	pcap_if_t* getDevsInfo();	// 获取所有网卡设备信息
};