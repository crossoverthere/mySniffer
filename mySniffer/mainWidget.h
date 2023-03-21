#pragma once

#include <QtWidgets/QMainWindow>
#include <qmessagebox.h>
#include "ui_mySniffer.h"
#include "packetCap.h"
#include "qSignal.h"

class MainWidget : public QMainWindow
{
    Q_OBJECT

public:
    MainWidget(QWidget *parent = nullptr);
    ~MainWidget();

private:
    Ui::mySnifferClass ui;
    PacketCapture* packetCap;

private slots:
    void click_on_capBtn();
    void click_on_uncapBtn();
    void select_on_netCmb();
    void select_on_filterCmb();

    /* 由后端触发 */
    void update_on_tableview(PKTDATA* data);     // 更新表格信息
    void receiveData(int v);

public:
    QSignal *qs;
};
