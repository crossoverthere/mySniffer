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

// 更新抓包信息
void MainWidget::select_on_tableview(int row, int col) {
    PKTDATA* data = packetCap->getData(row);
    QTreeWidgetItem* topItem = NULL;
    QTreeWidgetItem* twoLevelItem = NULL;
    QTreeWidgetItem* thrLevelItem = NULL;
    QString str;

    // 更新抓包信息
    ui.treeWidget->clear();
    str = QString::asprintf("捕获的第%d个数据包", row + 1);
    topItem = new QTreeWidgetItem(ui.treeWidget);
    topItem->setText(0, str);

    /* 链路层数据 */
    str = "链路层数据";
    topItem = new QTreeWidgetItem(ui.treeWidget);
    topItem->setText(0, str);
    str = "源MAC: " + ui.tableWidget->item(row, 4)->text();
    twoLevelItem = new QTreeWidgetItem(topItem);
    twoLevelItem->setText(0, str);
    str = "目的MAC: " + ui.tableWidget->item(row, 5)->text();
    twoLevelItem = new QTreeWidgetItem(topItem);
    twoLevelItem->setText(0, str);
    str = QString::asprintf("类型: 0x%04x", data->mach->type);
    twoLevelItem = new QTreeWidgetItem(topItem);
    twoLevelItem->setText(0, str);

    /* 网络层数据 IP, ARP IPv6 */
    switch (data->mach->type)
    {
    case 0x0806:
        str = "ARP协议";
        topItem = new QTreeWidgetItem(ui.treeWidget);
        topItem->setText(0, str);
        str = QString::asprintf("硬件类型: %d", data->arph->hrdType);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("协议类型: 0x%04x", data->arph->proType);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("硬件地址长度: %dbyte", data->arph->hrdLen);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("协议地址长度: %dbyte", data->arph->proLen);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("操作类型: %d", data->arph->op);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("发送方MAC: %02X-%02X-%02X-%02X-%02X-%02X", data->arph->srcMAC[0],
            data->arph->srcMAC[1], data->arph->srcMAC[2], data->arph->srcMAC[3], data->arph->srcMAC[4], data->arph->srcMAC[5]);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("发送方IP: %d.%d.%d.%d", data->arph->srcIP[0], 
            data->arph->srcIP[1], data->arph->srcIP[2], data->arph->srcIP[3]);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("接收方MAC: %02X-%02X-%02X-%02X-%02X-%02X", data->arph->destMAC[0],
            data->arph->destMAC[1], data->arph->destMAC[2], data->arph->destMAC[3], data->arph->destMAC[4], data->arph->destMAC[5]);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("接收方IP: %d.%d.%d.%d", data->arph->destIP[0],
            data->arph->destIP[1], data->arph->destIP[2], data->arph->destIP[3]);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        break;

    case 0x0800:
        str = "IP协议";
        topItem = new QTreeWidgetItem(ui.treeWidget);
        topItem->setText(0, str);
        str = QString::asprintf("版本号: %d", data->iph->version);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("报头长度: %d=%dbyte", data->iph->hdrLen, data->iph->hdrLen * 4);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("服务类型: 0x%02x", data->iph->tos);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("IP包总长: %dbyte", data->iph->tLen);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("标识: 0x%04x", data->iph->id);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = "标志位";
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("DF: %d", data->iph->flag % 2);
        thrLevelItem = new QTreeWidgetItem(twoLevelItem);
        thrLevelItem->setText(0, str);
        str = QString::asprintf("MF: %d", data->iph->flag / 2 % 2);
        thrLevelItem = new QTreeWidgetItem(twoLevelItem);
        thrLevelItem->setText(0, str);
        str = QString::asprintf("片偏移: 0x%x%02x", data->iph->off1, data->iph->off2);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("生存期: %d", data->iph->ttl);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("协议: %d", data->iph->proto);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("首部校验和: 0x%04x", data->iph->check);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = "源IP: " + ui.tableWidget->item(row, 6)->text();
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = "目的IP: " + ui.tableWidget->item(row, 7)->text();
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);

        /* 处理传输层 ICMP TCP UDP */
        switch (data->iph->proto)
        {
        case 1:
            str = "ICMP协议";
            topItem = new QTreeWidgetItem(ui.treeWidget);
            topItem->setText(0, str);
            str = QString::asprintf("类型: %d", data->icmph->type);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("代码: %d", data->icmph->code);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("校验和: 0x%04x", data->icmph->check);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            break;

        case 6:
            str = "TCP协议";
            topItem = new QTreeWidgetItem(ui.treeWidget);
            topItem->setText(0, str);
            str = QString::asprintf("源端口: %d", data->tcph->srcPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("目的端口: %d", data->tcph->destPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("序号: %u", data->tcph->seq);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("确认号: %u", data->tcph->ack_seq);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("首部长度: %dbyte", data->tcph->doff * 4);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = "标志位";
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("保留位: 0x%x%x", data->tcph->res1, data->tcph->res2);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("URG: %d", data->tcph->urg);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("ACK: %d", data->tcph->ack);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("PSH: %d", data->tcph->psh);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("RST: %d", data->tcph->rst);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("SYN: %d", data->tcph->syn);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("FIN: %d", data->tcph->fin);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("窗口大小: %d", data->tcph->window);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("校验和: 0x%04x", data->tcph->check);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("紧急指针: 0x%04x", data->tcph->urgPtr);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            break;

        case 17:
            str = "UDP协议";
            topItem = new QTreeWidgetItem(ui.treeWidget);
            topItem->setText(0, str);
            str = QString::asprintf("源端口: %d", data->udph->srcPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("目的端口: %d", data->udph->destPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("总长度: %d", data->udph->len);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("校验和: 0x%04x", data->udph->check);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            break;

        default:
            break;
        }
        break;

    case 0x86dd:
        str = "IPv6协议";
        topItem = new QTreeWidgetItem(ui.treeWidget);
        topItem->setText(0, str);
        str = QString::asprintf("版本: %d", data->ip6h->version);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("流类型: 0x%x%x", data->ip6h->flowType1, data->ip6h->flowType2);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("流标签: 0x%x%04x", data->ip6h->flowLabel1, data->ip6h->flowLabel2);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("有效载荷长度: %d", data->ip6h->plen);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("下一个报头: %d", data->ip6h->nh);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = QString::asprintf("跳跃限制: %d", data->ip6h->hlim);
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = "源IP: " + ui.tableWidget->item(row, 6)->text();
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);
        str = "目的IP" + ui.tableWidget->item(row, 7)->text();
        twoLevelItem = new QTreeWidgetItem(topItem);
        twoLevelItem->setText(0, str);

        /* 处理传输层 ICMP TCP UDP */
        switch (data->ip6h->nh)
        {
        case 0x3a:
            str = "ICMPv6协议";
            topItem = new QTreeWidgetItem(ui.treeWidget);
            topItem->setText(0, str);
            str = QString::asprintf("类型: %d", data->icmp6h->type);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("代码: %d", data->icmp6h->code);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("校验和: 0x%04x", data->icmp6h->chksum);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            break;

        case 6:
            str = "TCP协议";
            topItem = new QTreeWidgetItem(ui.treeWidget);
            topItem->setText(0, str);
            str = QString::asprintf("源端口: %d", data->tcph->srcPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("目的端口: %d", data->tcph->destPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("序号: %u", data->tcph->seq);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("确认号: %u", data->tcph->ack_seq);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("首部长度: %d=%dbyte", data->tcph->doff, data->tcph->doff * 4);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = "标志位";
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("保留位: 0x%x%x", data->tcph->res1, data->tcph->res2);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("URG: %d", data->tcph->urg);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("ACK: %d", data->tcph->ack);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("PSH: %d", data->tcph->psh);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("RST: %d", data->tcph->rst);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("SYN: %d", data->tcph->syn);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("FIN: %d", data->tcph->fin);
            thrLevelItem = new QTreeWidgetItem(twoLevelItem);
            thrLevelItem->setText(0, str);
            str = QString::asprintf("窗口大小: %d", data->tcph->window);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("校验和: 0x%04x", data->tcph->check);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("紧急指针: 0x%04x", data->tcph->urgPtr);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            break;

        case 17:
            str = "UDP协议";
            topItem = new QTreeWidgetItem(ui.treeWidget);
            topItem->setText(0, str);
            str = QString::asprintf("源端口: %d", data->udph->srcPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("目的端口: %d", data->udph->destPort);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("总长度: %d", data->udph->len);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            str = QString::asprintf("校验和: 0x%04x", data->udph->check);
            twoLevelItem = new QTreeWidgetItem(topItem);
            twoLevelItem->setText(0, str);
            break;

        default:
            break;
        }
        break;

    default:
        break;
    }
    ui.treeWidget->expandAll();
    
    // 对数据格式化显示
    unsigned char* pkt = data->pktData;
    int size = data->len;
    unsigned int i = 0;
    int rowcount = 0;
    unsigned char ch;

    ui.plainTextEdit->clear();
    ui.plainTextEdit->setTabStopDistance(20);
    // 申请一个进度条窗口
    QProgressDialog* progressDlg = new QProgressDialog(this);     
    progressDlg->setWindowModality(Qt::WindowModal);
    progressDlg->setMinimumDuration(0);
    progressDlg->setWindowTitle("Please Wait");
    progressDlg->setLabelText("Loading...");
    progressDlg->setCancelButtonText(nullptr);
    progressDlg->setRange(0, size);

    for (i; i < size; i+=16) {
        // 显示地址
        ui.plainTextEdit->appendPlainText(QString::asprintf("%04x:\t\t", i));
        // 显示16进制数据
        rowcount = (size - i) > 16 ? 16 : (size - i);
        for (int j = 0; j < rowcount; j++) {
            ui.plainTextEdit->insertPlainText(QString::asprintf("%02x\t", pkt[i + j]));
        }
        if (rowcount < 16) {
            for (int j = rowcount; j < 16; j++) {
                ui.plainTextEdit->insertPlainText(QString::asprintf("\t"));
            }
        }
        ui.plainTextEdit->insertPlainText(QString::asprintf("\t", i));
        // 显示字符数据
        for (int j = 0; j < rowcount; j++) {
            ch = pkt[i + j];
            ch = isprint(ch) ? ch : '.';
            ui.plainTextEdit->insertPlainText(QString::asprintf("%c", ch));
        }
        progressDlg->setValue(i);
    }
    progressDlg->setValue(size);
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