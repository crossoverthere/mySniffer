﻿#include "mainWidget.h"

MainWidget::MainWidget(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    qs = new QSignal();
    packetCap = new PacketCapture(qs);

    // 初始化网卡列表选项
    QString devName;
    int i = 0;
    if (packetCap->hasDevs()) {
        pcap_if_t* allDevs = packetCap->getDevsInfo();
        for (auto pdev = allDevs; pdev;) {
            if (pdev->description) {
                devName = pdev->description;
            }
            else {
                devName = pdev->name;
            }
            devName = QString::number(++i) + ". " + devName;
            ui.comboBox_net->addItem(devName);
            pdev = pdev->next;
        }
    }
    else
    {
        ui.comboBox_net->clear();
        ui.comboBox_net->addItem("未发现网卡设备");
    }

    // 设置connect
    connect(qs, SIGNAL(testSignal(int)), this, SLOT(receiveData(int)));
    connect(qs, SIGNAL(labelSignal(PKTDATA*)), this, SLOT(update_on_tableview(PKTDATA*)));
}

MainWidget::~MainWidget()
{
    delete qs;
    delete packetCap;
}

void MainWidget::click_on_capBtn() {
    // 开启抓包进程
    packetCap->setFlag(true);
    int res = packetCap->initCapture();

    if (res == 1) {
        ui.Btn_cap->setText("已开启");
    }

    ui.Btn_cap->setEnabled(false);
    ui.Btn_uncap->setEnabled(true);
}

void MainWidget::click_on_uncapBtn() {
    packetCap->setFlag(false);
    ui.Btn_cap->setEnabled(true);
    ui.Btn_uncap->setEnabled(false);
}

void MainWidget::select_on_netCmb() {
    int idx = ui.comboBox_net->currentIndex();
    // 根据当前项设置监听网卡设备
    this->packetCap->setDev(idx);
}

void MainWidget::select_on_filterCmb() {
    QString filter;
    if (ui.comboBox_filter->currentIndex() == 0) {
        filter = "";
    }
    else {
        filter = ui.comboBox_filter->currentText();
    }
    filter = filter.toLower();
    // 根据当前项设置过滤规则
    this->packetCap->setFilter(filter.toStdString());
}

// 接收后端信号，并作出响应
void MainWidget::receiveData(int v) {
    ui.comboBox_filter->addItem(QString::number(v));
}

// 更新lable表格
void::MainWidget::update_on_tableview(PKTDATA* data) {
    //ui.Btn_uncap->setText("sucess");
    QString str;
    int row = ui.tableWidget->rowCount();
    ui.tableWidget->setRowCount(row + 1);
    // 显示序号
    str = QString::number(row + 1);
    ui.tableWidget->setItem(row, 0, new QTableWidgetItem(str));
    // 显示时间戳
    str = QString::asprintf("%d/%d/%d-%d:%d:%d",
        data->time[0], data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
    ui.tableWidget->setItem(row, 1, new QTableWidgetItem(str));
    // 显示协议
    str = QString(data->pktType);
    ui.tableWidget->setItem(row, 2, new QTableWidgetItem(str));
    // 显示长度
    str = QString::asprintf("%d", data->len);
    ui.tableWidget->setItem(row, 3, new QTableWidgetItem(str));
    // 显示源MAC
    str = QString::asprintf("%02X-%02X-%02X-%02X-%02X-%02X", data->mach->src[0], data->mach->src[1],
        data->mach->src[2], data->mach->src[3], data->mach->src[4], data->mach->src[5]);
    ui.tableWidget->setItem(row, 4, new QTableWidgetItem(str));
    // 显示目的MAC
    str = QString::asprintf("%02X-%02X-%02X-%02X-%02X-%02X", data->mach->dest[0], data->mach->dest[1],
        data->mach->dest[2], data->mach->dest[3], data->mach->dest[4], data->mach->dest[5]);
    ui.tableWidget->setItem(row, 5, new QTableWidgetItem(str));
    // 显示源IP地址
    if (0x0806 == data->mach->type)
    {
        str = QString::asprintf("%d.%d.%d.%d", data->arph->srcIP[0],
            data->arph->srcIP[1], data->arph->srcIP[2], data->arph->srcIP[3]);
    }
    else if (0x0800 == data->mach->type) {
        struct  in_addr in;
        in.S_un.S_addr = data->iph->srcIP;
        str = QString(inet_ntoa(in));
    }
    else if (0x86dd == data->mach->type) {
        str = QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:", data->ip6h->srcAddr[0], data->ip6h->srcAddr[1], 
            data->ip6h->srcAddr[2], data->ip6h->srcAddr[3], data->ip6h->srcAddr[4], data->ip6h->srcAddr[5], data->ip6h->srcAddr[6], 
            data->ip6h->srcAddr[7]);
    }
    ui.tableWidget->setItem(row, 6, new QTableWidgetItem(str));
    // 显示目的IP地址

}