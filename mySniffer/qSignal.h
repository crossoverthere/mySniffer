#pragma once

#include <QObject>

/******************************
// 自定义QT信号类
// 用于前后端数据通信
******************************/

class QSignal  : public QObject
{
	Q_OBJECT

public:
	QSignal();
	~QSignal();

public:
	void emit_signal(int i) {
		emit sendData(i);
	}

signals:
	void sendData(int v);
};
