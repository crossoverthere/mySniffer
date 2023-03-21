#include "packetCap.h"


PacketCapture::PacketCapture(QSignal* p) {
	this->pdev = NULL;
	this->handle = NULL;
	this->capThreadHandle = NULL;
	this->qs = p;

	// 初始化网卡设备信息
	if (pcap_findalldevs(&allDevs, errBuf) == -1) {
		allDevs = NULL;
	}
}

PacketCapture::~PacketCapture(){
	if (allDevs != NULL) {
		pcap_freealldevs(allDevs);
	}
}

bool PacketCapture::hasDevs() {
	if (allDevs != NULL) {
		return true;
	}
	else {
		return false;
	}
}

pcap_if_t* PacketCapture::getDevsInfo() {
	return this->allDevs;
}

void PacketCapture::setDev(int idx) {
	// 设置所选网卡设备
	if (idx != 0) {
		pdev = allDevs;
		idx--;
		while (idx && (pdev != NULL)) {
			pdev = pdev->next;
			idx--;
		}
	}
	else {
		pdev = NULL;
	}
}

/* 设置过滤器 */
void PacketCapture::setFilter(string flt) {
	this->filter = flt;
}

/* 抓包前相关配置 */
int PacketCapture::initCapture() {
	bpf_program fp;
	bpf_u_int32 netmask;		// 网络掩码

	// 检测网卡设备合法性
	if (pdev == NULL) {
		return -1;
	}
	// 打开网卡接口
	handle = pcap_open_live(pdev->name, 65535, 1, 1000, errBuf);
	if (handle == NULL) {
		return -1;
	}

	// 检测是否为以太网
	if (pcap_datalink(handle) != DLT_EN10MB) {
		return -1;
	}

	// 编译过滤器
	if (pdev->addresses != NULL) {
		netmask = ((SOCKADDR_IN*)(pdev->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		netmask = 0xffffff;
	}
	if (pcap_compile(handle, &fp, filter.c_str(), 1, netmask) == PCAP_ERROR) {
		return -1;
	}

	// 设置过滤器
	if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
		return -1;
	}

	/* 开启一个线程 */
	LPDWORD threadCap = NULL;		// 线程标识符
	capThreadHandle = CreateThread(NULL, 0, captureThread, this, 0, threadCap);
	if (capThreadHandle == NULL) {
		return -1;
	}
	return 0;
}


/* 用于抓包的线程 */
DWORD WINAPI captureThread(LPVOID lpParameter) {
	PacketCapture* pthis = (PacketCapture*)lpParameter;

	pcap_pkthdr* pktHeader;			// 接收报文头部
	const uchar* pktData;			// 接收报文数据
	int res;

	// 数据报捕获
	while ((res = pcap_next_ex(pthis->handle, &pktHeader, &pktData) >= 0)) {
		// 超时
		if (res == 0) {
			continue;
		}	

		// 申请一份内存保存抓包信息
		PKTDATA* data = (PKTDATA*)malloc(sizeof(PKTDATA));
		if (data == NULL) {
			return -1;
		}
		else {
			memset(data, 0, sizeof(PKTDATA));
		}

		// 对报文数据进行分析

		// 保存数据包信息

		// 更新包统计

	}
	return 1;
}
