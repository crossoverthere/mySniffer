#pragma once

#include <QtWidgets/QMainWindow>
#include <qmessagebox.h>
#include "ui_mySniffer.h"
#include "packetCap.h"


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
};
