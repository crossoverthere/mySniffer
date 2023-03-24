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


/* 清空数据链表 */
void PacketCapture::clearAllData() {
	// 释放所有指针后，清空列表
	for (auto data : datalist) {
		data->freePtr();
		free(data);
	}
	datalist.clear();

	// 清除抓包统计
	memset(&npkt, 0, sizeof(PKTCOUNT));
}


/* 抓包前相关配置 */
int PacketCapture::initCapture(string& info) {
	bpf_program fp;
	bpf_u_int32 netmask;		// 网络掩码

	// 检测网卡设备合法性
	if (pdev == NULL) {
		info = "所选网卡不存在";
		return -1;
	}
	// 打开网卡接口
	handle = pcap_open_live(pdev->name, 65535, 1, 1000, errBuf);
	if (handle == NULL) {
		info = "无法打开网卡接口: " + string(pdev->description);
		return -1;
	}

	// 检测是否为以太网
	if (pcap_datalink(handle) != DLT_EN10MB) {
		info = "不适用非以太网络";
		return -1;
	}

	// 编译过滤器
	if (pdev->addresses != NULL) {
		netmask = ((SOCKADDR_IN*)(pdev->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		netmask = 0xffffff;
	}
	if (pcap_compile(handle, &fp, filter.c_str(), 1, netmask) < 0) {
		info = "编译失败，无法编译过滤器";
		return -1;
	}

	// 设置过滤器
	if (pcap_setfilter(handle, &fp) < 0) {
		info = "设置过滤器失败";
		return -1;
	}

	// 设置捕获数据存储路径

	// 设置线程控制字
	this->flag = true;
	/* 开启一个线程 */
	LPDWORD threadCap = NULL;		// 线程标识符
	capThreadHandle = CreateThread(NULL, 0, captureThread, this, 0, threadCap);
	if (capThreadHandle == NULL) {
		int code = GetLastError();
		info = "创建线程失败 " + code;
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
		emit pthis->qs->warningSignal("线程句柄错误");
	}

	// 清空上次抓包数据
	pthis->clearAllData();

	// 数据报捕获
	while ((res = pcap_next_ex(pthis->handle, &pktHeader, &pktData) >= 0) && (pthis->flag == true)) {
		// 超时
		if (res == 0) {
			continue;
		}	
		//emit pthis->qs->testSignal(1);
		//if (NULL == pktData) {
		//	continue;
		//}
		// 申请一份内存保存抓包信息
		PKTDATA* data = (PKTDATA*)malloc(sizeof(PKTDATA));
		if (data == NULL) {
			emit pthis->qs->warningSignal("空间已满，无法接收新数据");
			return -1;
		}
		else {
			memset(data, 0, sizeof(PKTDATA));
		}
		//return -1;
		// 对报文数据进行分析
		if (parsing_fram(pktData, data, &(pthis->npkt)) < 0) {
			free(data);
			continue;
		}

		// 保存数据包信息


		// 更新抓包统计(主窗体)
		emit pthis->qs->statsSignal(&(pthis->npkt));


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
		emit pthis->qs->labelSignal(data);

		// 数据存入链表以用于后续调用
		pthis->datalist.push_back(data);
	}
	emit pthis->qs->warningSignal("抓包线程已经结束");
	return 1;
}
