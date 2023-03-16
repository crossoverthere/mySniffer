#include "mySniffer.h"

mySniffer::mySniffer(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
}

mySniffer::~mySniffer()
{}

void mySniffer::click_on_cap() {
    ui.button_uncap->setEnabled(true);
    ui.button_cap->setDisabled(true);
}