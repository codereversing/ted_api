#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <functional>
#include <memory>

#include <QMainWindow>

#include <QList>
#include <QMap>
#include <QPair>
#include <QSet>
#include <QString>
#include <QTableWidgetItem>
#include <QThread>

#include "thirdparty/include/TEDClientBridge.h"

class BreakpointListenThread : public QThread
{
    Q_OBJECT

public:
    BreakpointListenThread(TED_Client ** client, TED_BreakpointReader ** reader)
        : m_client{client}
        , m_reader{reader}
    { }

    void run() override
    {
        while (true) {
            if (m_client != nullptr && m_reader != nullptr) {
                std::shared_ptr<TED_BreakpointResponse> response{
                    TED_GetBreakpointFnc(*m_client, *m_reader), TED_DestroyBreakpointFnc };
                if (response != nullptr) {
                    emit breakpointEventReceived(response);
                } else {
                    this->msleep(100);
                }
            }
        }
    }

signals:
    void breakpointEventReceived(std::shared_ptr<TED_BreakpointResponse> response);

private:
    TED_Client ** m_client;
    TED_BreakpointReader ** m_reader;
};

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget * parent = nullptr);
    ~MainWindow();

private slots:
    void on_action_Exit_triggered();
    void on_action_Return_context_triggered(bool checked);
    void on_action_Return_call_stack_triggered(bool checked);
    void on_action_Return_symbols_triggered(bool checked);
    void on_action_Set_symbol_path_triggered();
    void on_action_Enable_console_triggered(bool checked);
    void on_action_Enable_logging_triggered(bool checked);
    void on_action_Invoke_test_function_triggered();
    void on_action_Attach_triggered();
    void on_action_Get_modules_triggered();
    void on_action_Disassemble_address_triggered();
    void on_action_Memory_triggered();
    void on_tableWidget_Calls_cellDoubleClicked(int row, int column);
    void on_action_Use_invasive_breakpoints_triggered(bool checked);
    void on_action_Unsafe_memory_mode_triggered(bool checked);
    void on_action_Disable_all_shown_triggered();
    void on_action_Disable_custom_triggered();
    void on_action_Enable_all_shown_triggered();
    void on_action_Enable_custom_triggered();
    void on_action_Clear_triggered();
    void on_action_Auto_disable_incoming_triggered(bool checked);
    void on_tableWidget_Calls_customContextMenuRequested(const QPoint &pos);
    void on_action_About_triggered();

public slots:
    void handleBreakpointResult(std::shared_ptr<TED_BreakpointResponse> response);

private:
    Ui::MainWindow * ui;

    void sendOptionsUpdate();

    QPair<QString, uint64_t> getModuleNameAndOffsetForAddress(uint64_t address);

    TED_Client * m_client;
    TED_BreakpointReader * m_breakpointReader;

    QSet<QString> m_activeModules;
    QMap<QPair<uint64_t, uint64_t>, QString> m_moduleAddressRanges;

    QString m_symbolPath;
    QMap<QString, QList<QTableWidgetItem *> > m_addressToRow;
    QMap<QString, std::shared_ptr<TED_BreakpointResponse> > m_lastBreakpointInfo;

    std::unique_ptr<BreakpointListenThread> m_breakpointListenThread;

    bool m_showOffsets;
};
#endif // MAINWINDOW_H
