#pragma once

#include <QtWidgets/QMainWindow>
#include <qmessagebox.h>
#include <qheaderview.h>
#include <qtablewidget.h>
#include <QProgressDialog>
#include "ui_mySniffer.h"
#include "packetCap.h"
#include "qSignal.h"

class MainWidget : public QMainWindow
{
    Q_OBJECT

public:
    MainWidget(QWidget *parent = nullptr);
    ~MainWidget();
    void initUI();                              // 初始化一些UI设置
 
private:
    Ui::mySnifferClass ui;
    PacketCapture* packetCap;

private slots:
    void click_on_capBtn();
    void click_on_uncapBtn();
    void select_on_netCmb();
    void select_on_filterCmb();
    void select_on_tableview(int row, int col);
    void click_on_traceBtn();

    /* 由后端触发 */
    void update_on_tableview(PKTDATA* data);        // 更新表格信息
    void updata_stats(PKTCOUNT* npkt);              // 更新抓包统计
    void sendWarning(QString str);                  // 触发警告窗口
    void sendCritical(QString str);                 // 触发错误窗口 
    void receiveData(int v);

public:
    QSignal *qs;
};
