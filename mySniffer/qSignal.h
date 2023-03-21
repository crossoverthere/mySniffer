#pragma once

/******************************
* 自定义QT信号类
* 用于前后端数据通信
******************************/

#include <QObject>
#include "protocol.h"


class QSignal  : public QObject
{
	Q_OBJECT

public:
	QSignal();
	~QSignal();

signals:
	void labelSignal(PKTDATA* data);
signals:
	void testSignal(int i);
};
