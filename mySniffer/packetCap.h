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
//typedef std::list<PKTDATA*> DataList;
typedef std::vector<PKTDATA*> DataList;

DWORD WINAPI captureThread(LPVOID lpParam);

class PacketCapture {
public:
	PacketCapture(QSignal* p);
	~PacketCapture();

private:
	QSignal* qs;					// 自定义信号类
	PKTCOUNT npkt;					// 抓包统计
	DataList datalist;				// 数据链表
	bool flag;						// 线程终止标志

	pcap_if_t* allDevs;				// 所有网卡设备
	pcap_if_t* pdev;
	pcap_t* handle;					// 网卡接口
	string filter;					// 过滤器
	//pcap_dumper_t* dumpfp;
	//char fname[64];				// 存储文件
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
	void clearAllData();				// 清空数据链表
	PKTDATA* getData(int index);		// 从链表中取一个数据

	friend DWORD WINAPI captureThread(LPVOID lpParam);
};