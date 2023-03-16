#include "mainWidget.h"

MainWidget::MainWidget(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    packetCap = new PacketCapture();

    // 检测有无网卡设备
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
    ui.button_uncap->setEnabled(true);
    ui.button_cap->setDisabled(true);
}