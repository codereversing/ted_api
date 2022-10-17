#ifndef DISASSEMBLEADDRESSWINDOW_H
#define DISASSEMBLEADDRESSWINDOW_H

#include <QDialog>
#include <QString>

#include "thirdparty/include/TEDClientBridge.h"

namespace Ui {
class DisassembleAddressWindow;
}

class DisassembleAddressWindow : public QDialog
{
    Q_OBJECT

public:
    explicit DisassembleAddressWindow(TED_Client * client, QWidget * parent = nullptr);
    ~DisassembleAddressWindow();

private slots:
    void on_pushButton_Close_clicked();

    void on_pushButton_Disassemble_clicked();

private:
    Ui::DisassembleAddressWindow * ui;

    TED_Client * m_client;
};

#endif // DISASSEMBLEADDRESSWINDOW_H
