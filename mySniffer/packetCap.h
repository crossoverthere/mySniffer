#pragma once
/*********************
// 实现对数据捕获
**********************/

#include <pcap.h>
#include <string>
#include "qSignal.h"
#include "protocol.h"
#include "utils.h"

typedef std::string string;

DWORD WINAPI captureThread(LPVOID lpParam);

class PacketCapture {
public:
	PacketCapture(QSignal* p);
	~PacketCapture();

private:
	QSignal* qs;					// 自定义信号类
	PKTCOUNT npkt;					// 抓包统计
	bool flag;						// 线程终止标志

	pcap_if_t* allDevs;				// 所有网卡设备
	pcap_if_t* pdev;
	pcap_t* handle;					// 网卡接口
	string filter;					// 过滤器
	//pcap_dumper_t* dumpfp;
	//char fname[64];					// 存储文件
	//char fpath[512];
	HANDLE capThreadHandle;			// 线程handle

	char errBuf[PCAP_ERRBUF_SIZE];


public:
	bool hasDevs();				
	pcap_if_t* getDevsInfo();			// 获取所有网卡设备信息
	void setDev(int idx);				// 设置监听的网卡设备
	void setFilter(string flt);			// 设置过滤器
	void setFlag(bool f);
	int initCapture(string& info);		// 初始化
	void updateNPKT();					// 更新抓包统计
	void updateTableView(PKTDATA* data);// 更新抓包列表

	friend DWORD WINAPI captureThread(LPVOID lpParam);
};