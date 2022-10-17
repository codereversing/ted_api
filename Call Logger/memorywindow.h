#ifndef MEMORYWINDOW_H
#define MEMORYWINDOW_H

#include <QDialog>
#include <QMap>
#include <QTableWidgetItem>

#include "thirdparty/include/TEDClientBridge.h"

namespace Ui {
class MemoryWindow;
}

class MemoryWindow : public QDialog
{
    Q_OBJECT

public:
    explicit MemoryWindow(TED_Client * client, QWidget * parent = nullptr);
    ~MemoryWindow();

private slots:
    void on_pushButton_Close_clicked();
    void on_pushButton_Save_clicked();
    void on_pushButton_Read_clicked();
    void on_tableWidget_Bytes_itemChanged(QTableWidgetItem * item);
    void on_tableWidget_Bytes_itemSelectionChanged();

private:
    Ui::MemoryWindow * ui;

    TED_Client * m_client;

    QMap<QString, QString> m_previousByteValues;
};

#endif // MEMORYWINDOW_H
