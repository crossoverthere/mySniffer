#include "mainWidget.h"

MainWidget::MainWidget(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    initUI();

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
    connect(qs, SIGNAL(statsSignal(PKTCOUNT*)), this, SLOT(updata_stats(PKTCOUNT*)));
    connect(qs, SIGNAL(warningSignal(QString)), this, SLOT(sendWarning(QString)));
    connect(qs, SIGNAL(criticalSignal(QString)), this, SLOT(sendCritical(QString)));
}

MainWidget::~MainWidget()
{
    delete qs;
    delete packetCap;
}

void MainWidget::initUI() {
    ui.tableWidget->setColumnWidth(0, 50);
    ui.tableWidget->setColumnWidth(1, 120);
    ui.tableWidget->setColumnWidth(2, 60);
    ui.tableWidget->setColumnWidth(3, 50);
    ui.tableWidget->setColumnWidth(4, 130);
    ui.tableWidget->setColumnWidth(5, 130);
    ui.tableWidget->setColumnWidth(6, 250);
    ui.tableWidget->setColumnWidth(7, 250);
    ui.tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    ui.tableWidget->verticalHeader()->setHidden(true);
    ui.tableWidget->setSelectionBehavior(QTableWidget::SelectRows);
}

void MainWidget::click_on_capBtn() {
    string erroinfo;
    // 清空抓包列表
    ui.tableWidget->clearContents();
    ui.tableWidget->setRowCount(0);
    // 清空统计记录
    ui.lEdit_nip->setText(QString::number(0));
    ui.lEdit_nip6->setText(QString::number(0));
    ui.lEdit_narp->setText(QString::number(0));
    ui.lEdit_ntcp->setText(QString::number(0));
    ui.lEdit_nudp->setText(QString::number(0));
    ui.lEdit_nhttp->setText(QString::number(0));
    ui.lEdit_nicmp->setText(QString::number(0));
    ui.lEdit_nicmp6->setText(QString::number(0));
    ui.lEdit_sum->setText(QString::number(0));
    ui.lEdit_other->setText(QString::number(0));
    // 开启抓包进程
    if (packetCap->initCapture(erroinfo) == -1) {
        sendWarning(QString::fromStdString(erroinfo));
    }
    else {
        ui.Btn_cap->setEnabled(false);
        ui.Btn_uncap->setEnabled(true);
        ui.comboBox_net->setEnabled(false);
        ui.comboBox_filter->setEnabled(false);
    }
}

void MainWidget::click_on_uncapBtn() {
    packetCap->setFlag(false);
    ui.Btn_cap->setEnabled(true);
    ui.Btn_cap->setText("重新开始");

    ui.Btn_uncap->setEnabled(false);
    ui.comboBox_net->setEnabled(true);
    ui.comboBox_filter->setEnabled(true);
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

void MainWidget::select_on_tableview(int row, int col) {
    QString str = QString::number(row);
    ui.label->setText(str + "success");
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
        in_addr in;
        in.S_un.S_addr = data->iph->srcIP;
        str = QString(inet_ntoa(in));
    }
    else if (0x86dd == data->mach->type) {
        str = QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", data->ip6h->srcAddr[0], data->ip6h->srcAddr[1], 
            data->ip6h->srcAddr[2], data->ip6h->srcAddr[3], data->ip6h->srcAddr[4], data->ip6h->srcAddr[5], data->ip6h->srcAddr[6], 
            data->ip6h->srcAddr[7]);
    }
    ui.tableWidget->setItem(row, 6, new QTableWidgetItem(str));
    // 显示目的IP地址
    if (0x0806 == data->mach->type) {
        str = QString::asprintf("%d.%d.%d.%d", data->arph->destIP[0],
            data->arph->destIP[1], data->arph->destIP[2], data->arph->destIP[3]);
    }
    else if (0x0800 == data->mach->type) {
        in_addr in;
        in.S_un.S_addr = data->iph->destIP;
        str = QString(inet_ntoa(in));
    }
    else if (0x86dd == data->mach->type) {
        str = QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", data->ip6h->destAddr[0], data->ip6h->destAddr[1],
            data->ip6h->destAddr[2], data->ip6h->destAddr[3], data->ip6h->destAddr[4], data->ip6h->destAddr[5], data->ip6h->destAddr[6],
            data->ip6h->destAddr[7]);

    }
    ui.tableWidget->setItem(row, 7, new QTableWidgetItem(str));
}

// 更新抓包统计
void MainWidget::updata_stats(PKTCOUNT* npkt) {
    ui.lEdit_nip->setText(QString::number(npkt->n_ip));
    ui.lEdit_nip6->setText(QString::number(npkt->n_ip6));
    ui.lEdit_narp->setText(QString::number(npkt->n_arp));
    ui.lEdit_ntcp->setText(QString::number(npkt->n_tcp));
    ui.lEdit_nudp->setText(QString::number(npkt->n_udp));
    ui.lEdit_nhttp->setText(QString::number(npkt->n_http));
    ui.lEdit_nicmp->setText(QString::number(npkt->n_icmp));
    ui.lEdit_nicmp6->setText(QString::number(npkt->n_icmp6));
    ui.lEdit_sum->setText(QString::number(npkt->n_sum));
    ui.lEdit_other->setText(QString::number(npkt->n_other));
}


/* 提示窗口 */
void MainWidget::sendWarning(QString str) {
    QMessageBox::warning(this, tr("Warning"), str, 
        QMessageBox::Ok, QMessageBox::Ok);
}
void MainWidget::sendCritical(QString str) {
    QMessageBox::critical(this, tr("Error"), str,
        QMessageBox::Ok, QMessageBox::Ok);
}