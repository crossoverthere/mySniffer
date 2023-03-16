#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_mySniffer.h"

class mySniffer : public QMainWindow
{
    Q_OBJECT

public:
    mySniffer(QWidget *parent = nullptr);
    ~mySniffer();

private:
    Ui::mySnifferClass ui;

private slots:
    void click_on_cap();
};
