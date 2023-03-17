#include "packetCap.h"


PacketCapture::PacketCapture() {
	this->pdev = NULL;
	this->handle = NULL;

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

void PacketCapture::setFilter(QString& flt) {
	this->filter = flt.toStdString();
}

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
	return 0;
}

