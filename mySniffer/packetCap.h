#pragma once
/*********************
// 实现对数据捕获
**********************/

#include <pcap.h>
#include <string>
#include <QString>
#include "qSignal.h"

DWORD WINAPI captureThread(LPVOID lpParam);

class PacketCapture {
public:
	PacketCapture(QSignal* p);
	~PacketCapture();

private:
	QSignal* qs;					// 自定义信号类

	pcap_if_t* allDevs;				// 所有网卡设备
	pcap_if_t* pdev;
	pcap_t* handle;					// 网卡接口
	std::string filter;				// 过滤器
	HANDLE capThreadHandle;			// 线程

	char errBuf[PCAP_ERRBUF_SIZE];

public:
	bool hasDevs();				
	pcap_if_t* getDevsInfo();		// 获取所有网卡设备信息
	void setDev(int idx);			// 设置监听的网卡设备
	void setFilter(QString& flt);	// 设置过滤器
	int initCapture();				// 初始化
};