#include "mainWidget.h"

MainWidget::MainWidget(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    packetCap = new PacketCapture();

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
}

MainWidget::~MainWidget()
{
    delete packetCap;
}

void MainWidget::click_on_capBtn() {
    ui.Btn_cap->setEnabled(false);
    ui.Btn_uncap->setEnabled(true);
}

void MainWidget::click_on_uncapBtn() {
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
    this->packetCap->setFilter(filter);
}