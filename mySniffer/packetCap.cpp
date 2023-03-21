#include "packetCap.h"


PacketCapture::PacketCapture(QSignal* p) {
	this->pdev = NULL;
	this->handle = NULL;
	this->capThreadHandle = NULL;
	this->qs = p;
	this->flag = true;

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

void PacketCapture::setFlag(bool f) {
	this->flag = f;
}


/* 更新抓包统计 */
void PacketCapture::updateNPKT() {

}

/* 更新抓包列表 */
void PacketCapture::updateTableView(PKTDATA* data) {
	emit qs->labelSignal(data);
	//emit qs->testSignal(1);
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

	// 设置捕获数据存储路径

	pcap_freealldevs(allDevs);

	/* 开启一个线程 */
	LPDWORD threadCap = NULL;		// 线程标识符
	capThreadHandle = CreateThread(NULL, 0, captureThread, this, 0, threadCap);
	if (capThreadHandle == NULL) {
		int code = GetLastError();
		return -1;
	}
	return 1;
}


/* 用于抓包的线程 */
DWORD WINAPI captureThread(LPVOID lpParameter) {
	PacketCapture* pthis = (PacketCapture*)lpParameter;

	struct tm* ltime;
	time_t local_tv_sec;

	pcap_pkthdr* pktHeader;			// 接收报文头部
	const uchar* pktData;			// 接收报文数据
	int res;

	if (NULL == pthis->capThreadHandle) {
		return -1;
	}

	// 数据报捕获
	while ((res = pcap_next_ex(pthis->handle, &pktHeader, &pktData) >= 0) && pthis->flag == true) {
		// 超时
		if (res == 0) {
			continue;
		}	
		//emit pthis->qs->testSignal(1);
		// 申请一份内存保存抓包信息
		PKTDATA* data = (PKTDATA*)malloc(sizeof(PKTDATA));
		if (data == NULL) {
			return -1;
		}
		else {
			memset(data, 0, sizeof(PKTDATA));
		}
		// 对报文数据进行分析
		if (parsing_fram(pktData, data, &(pthis->npkt)) < 0) {
			continue;
		}
		//emit pthis->qs->testSignal(1);

		// 保存数据包信息


		// 更新抓包统计(主窗体)
		pthis->updateNPKT();

		// 数据存入链表以用于后续调用


		// 处理时间、长度
		data->len = pktHeader->len;
		local_tv_sec = pktHeader->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;
		// 更新抓包列表(主窗体)
		pthis->updateTableView(data);
	}
	return 1;
}
