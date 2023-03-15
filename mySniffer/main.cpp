#include "mySniffer.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    mySniffer w;
    w.show();
    return a.exec();
}
