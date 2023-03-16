#include "packetCap.h"


PacketCapture::PacketCapture() {
	pdev = NULL;

	// 初始化网卡设备信息
	if (pcap_findalldevs(&allDevs, errBuf) == -1) {
		allDevs = NULL;
		errBuf = NULL;
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