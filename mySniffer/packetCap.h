#pragma once
/*********************
// 实现对数据捕获
**********************/

#include <pcap.h>
#include <string>
#include <QString>


class PacketCapture {
public:
	PacketCapture();
	~PacketCapture();

private:
	pcap_if_t* allDevs;				// 所有网卡设备
	pcap_if_t* pdev;
	pcap_t* handle;					// 网卡接口
	std::string filter;				// 过滤器

	char errBuf[PCAP_ERRBUF_SIZE];

public:
	bool hasDevs();				
	pcap_if_t* getDevsInfo();		// 获取所有网卡设备信息
	void setDev(int idx);			// 设置监听的网卡设备
	void setFilter(QString& flt);	// 设置过滤器
	int initCapture();				// 初始化
};