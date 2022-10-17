#ifndef PROCESSELECTWINDOW_H
#define PROCESSELECTWINDOW_H

#include <QDialog>

namespace Ui {
class ProcessSelectWindow;
}

class ProcessSelectWindow : public QDialog
{
    Q_OBJECT

public:
    explicit ProcessSelectWindow(QWidget *parent = nullptr);
    ~ProcessSelectWindow();

private slots:
    void on_pushButton_close_clicked();

    void on_pushButton_attach_clicked();

    void on_pushButton_refresh_clicked();

private:
    Ui::ProcessSelectWindow *ui;

    void refreshActiveProcesses();
};

#endif // PROCESSELECTWINDOW_H
