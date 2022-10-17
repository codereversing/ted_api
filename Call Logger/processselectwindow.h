#ifndef PROCESSELECTWINDOW_H
#define PROCESSELECTWINDOW_H

#include <QDialog>
#include <QTableWidgetItem>

#include <QString>

namespace Ui {
class ProcessSelectWindow;
}

class ProcessSelectWindow : public QDialog
{
    Q_OBJECT

public:
    explicit ProcessSelectWindow(QString * activeProcessName,
                                 QString * activeProcessId,
                                 QWidget * parent = nullptr);
    ~ProcessSelectWindow();

private slots:
    void on_pushButton_Close_clicked();
    void on_pushButton_Attach_clicked();
    void on_pushButton_Refresh_clicked();
    void on_tableWidget_Processes_itemDoubleClicked(QTableWidgetItem * item);
    void on_pushButton_Find_server_dll_clicked();

private:
    Ui::ProcessSelectWindow * ui;

    void refreshActiveProcesses();
    void attachToProcessAndClose();

    QString * m_activeProcessName;
    QString * m_activeProcessId;
};

#endif // PROCESSELECTWINDOW_H
