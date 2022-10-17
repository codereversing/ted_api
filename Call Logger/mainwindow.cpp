#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <memory>

#include <QClipboard>
#include <QFileDialog>
#include <QInputDialog>

#include "breakpointinfowindow.h"
#include "disassembleaddresswindow.h"
#include "errormessagedialog.h"
#include "memorywindow.h"
#include "moduleslistwindow.h"
#include "processselectwindow.h"

MainWindow::MainWindow(QWidget * parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_client{}
    , m_breakpointReader{}
    , m_symbolPath{}
    , m_activeModules{}
    , m_moduleAddressRanges{}
    , m_addressToRow{}
    , m_lastBreakpointInfo{}
    , m_breakpointListenThread{}
    , m_showOffsets{}
{
    ui->setupUi(this);

    ui->tableWidget_Calls->resizeColumnsToContents();
    ui->tableWidget_Calls->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

MainWindow::~MainWindow()
{
    delete ui;

    TED_DestroyBreakpointReaderFnc(m_client);
    TED_DestroyClientFnc(m_client);
}

void MainWindow::sendOptionsUpdate()
{
    TED_Options options{ };

    options.returnContext              = ui->action_Return_context->isChecked();
    options.returnCallStack            = ui->action_Return_call_stack->isChecked();
    options.returnSymbolInfo           = ui->action_Return_symbols->isChecked();
    options.useInvasiveBreakpoints     = ui->action_Use_invasive_breakpoints->isChecked();
    options.unsafeMemoryMode           = ui->action_Unsafe_memory_mode->isChecked();
    options.autoDisableBreakpointsMode = ui->action_Auto_disable_incoming->isChecked();
    options.killProcessOnDisconnect    = true;

    strncpy_s(options.symbolPath, m_symbolPath.toStdString().c_str(), m_symbolPath.length());

    std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
        TED_SetOptionsFnc(m_client, &options), TED_DestroyGenericFnc };
}

void MainWindow::on_action_Exit_triggered()
{
    QCoreApplication::quit();
}

void MainWindow::on_action_Return_context_triggered(bool checked)
{
    sendOptionsUpdate();
}

void MainWindow::on_action_Return_call_stack_triggered(bool checked)
{
    sendOptionsUpdate();
}

void MainWindow::on_action_Return_symbols_triggered(bool checked)
{
    sendOptionsUpdate();
}

void MainWindow::on_action_Use_invasive_breakpoints_triggered(bool checked)
{
    sendOptionsUpdate();
}

void MainWindow::on_action_Unsafe_memory_mode_triggered(bool checked)
{
    sendOptionsUpdate();
}

void MainWindow::on_action_Auto_disable_incoming_triggered(bool checked)
{
    sendOptionsUpdate();
}

void MainWindow::on_action_Set_symbol_path_triggered()
{
    auto symbolsPath{ QFileDialog::getExistingDirectory(
                          this, tr("Open Symbols Directory"),
                          "",
                          QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks)
    };

    if (!symbolsPath.isEmpty()) {
        m_symbolPath = symbolsPath;
    }

    sendOptionsUpdate();
}

void MainWindow::on_action_Enable_console_triggered(bool checked)
{
    std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{ { }, TED_DestroyGenericFnc };

    if (checked) {
        response.reset(TED_CreateConsoleFnc(m_client));
    } else {
        response.reset(TED_DestroyConsoleFnc(m_client));
    }
}

void MainWindow::on_action_Enable_logging_triggered(bool checked)
{
    std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{ { }, TED_DestroyGenericFnc };

    if (checked) {
        response.reset(TED_EnableInternalLoggingFnc(m_client));
    } else {
        response.reset(TED_DisableInternalLoggingFnc(m_client));
    }
}

void MainWindow::on_action_Invoke_test_function_triggered()
{
    std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
        TED_TestFunctionFnc(m_client), TED_DestroyGenericFnc };
}

void MainWindow::on_action_Attach_triggered()
{
    QString activeProcessName{ };
    QString activeProcessId{ };

    ProcessSelectWindow processSelectWindow{ &activeProcessName, &activeProcessId };

    processSelectWindow.show();
    processSelectWindow.exec();

    if (!activeProcessName.isEmpty() && !activeProcessId.isEmpty()) {

        this->ui->tableWidget_Calls->setRowCount(0);
        this->setWindowTitle("TED Call Logger - Attached to " +
            activeProcessName + " (" +
            activeProcessId + ")");

        m_addressToRow.clear();
        m_activeModules.clear();
        m_moduleAddressRanges.clear();
        m_lastBreakpointInfo.clear();

        m_client = TED_CreateClientFnc("localhost:50051");
        if (m_client != nullptr) {
            m_breakpointReader = TED_CreateBreakpointReaderFnc(m_client);
            if (m_breakpointReader != nullptr) {
                sendOptionsUpdate();

                if (m_breakpointListenThread == nullptr) {
                    m_breakpointListenThread.reset(
                        new BreakpointListenThread(&m_client, &m_breakpointReader));
                    this->connect(m_breakpointListenThread.get(), &BreakpointListenThread::breakpointEventReceived,
                      this, &MainWindow::handleBreakpointResult);
                    m_breakpointListenThread->start();

                    this->ui->action_Attach->setEnabled(false);
                } else {
                    ErrorMessageDialog::show("Could not initialize TED breakpoint reader");
                }
            }
        } else {
            ErrorMessageDialog::show("Could not initialize TED client");
        }
    }
}

void MainWindow::on_action_Get_modules_triggered()
{
    ModulesListWindow modulesListWindow{ m_client, &m_activeModules, &m_moduleAddressRanges };

    modulesListWindow.show();
    modulesListWindow.exec();
}

void MainWindow::on_action_Disassemble_address_triggered()
{
    DisassembleAddressWindow disassembleAddressWindow{ m_client };

    disassembleAddressWindow.show();
    disassembleAddressWindow.exec();
}

void MainWindow::on_action_Memory_triggered()
{
    MemoryWindow memoryWindow{ m_client };

    memoryWindow.show();
    memoryWindow.exec();
}

void MainWindow::handleBreakpointResult(std::shared_ptr<TED_BreakpointResponse> response)
{
    auto address{ QString::number(response->sourceAddress) + "," + QString::number(response->destinationAddress) };

    m_lastBreakpointInfo[address] = response;

    int count{ 1 };

    if (m_addressToRow.contains(address)) {
        if (response->callStack.stackFramesCount > 0 &&
          response->callStack.stackFrames[0]->symbols.functionNameLength > 0)
        {
            m_addressToRow[address].at(2)->setText(response->callStack.stackFrames[0]->symbols.functionName);
        }

        count = m_addressToRow[address].at(3)->text().toULongLong();
        count++;
        m_addressToRow[address].at(3)->setText(QString::number(count));
    } else {
        this->ui->tableWidget_Calls->insertRow(this->ui->tableWidget_Calls->rowCount());

        auto sourceAddress{ new NumericTableWidgetItem(
                                QString::number(response->sourceAddress, 16), 16) };
        auto destinationAddress{ new NumericTableWidgetItem(
                                     QString::number(response->destinationAddress, 16), 16) };
        QString destinationNameStr{ "" };
        if (response->callStack.stackFramesCount > 0 &&
          response->callStack.stackFrames[0]->symbols.functionNameLength > 0)
        {
            destinationNameStr = response->callStack.stackFrames[0]->symbols.functionName;
        }
        auto destinationName{ new QTableWidgetItem(destinationNameStr) };
        auto hitCount{ new NumericTableWidgetItem(QString::number(count)) };

        auto insertRow{ this->ui->tableWidget_Calls->rowCount() - 1 };
        this->ui->tableWidget_Calls->setItem(insertRow, 0, sourceAddress);
        this->ui->tableWidget_Calls->setItem(insertRow, 1, destinationAddress);
        this->ui->tableWidget_Calls->setItem(insertRow, 2, destinationName);
        this->ui->tableWidget_Calls->setItem(insertRow, 3, hitCount);

        m_addressToRow[address] = QList<QTableWidgetItem *>{ {
            sourceAddress, destinationAddress, destinationName, hitCount } };
    }
}

void MainWindow::on_tableWidget_Calls_cellDoubleClicked(int row, int column)
{
    bool ok1{ }, ok2{ };
    auto address { QString::number(this->ui->tableWidget_Calls->item(row, 0)->text().toULongLong(&ok1, 16))
                   + ","
                   + QString::number(this->ui->tableWidget_Calls->item(row, 1)->text().toULongLong(&ok2, 16)) };

    if (ok1 && ok2 && m_lastBreakpointInfo.contains(address)) {
        BreakpointInfoWindow breakpointInfoWindow{ m_lastBreakpointInfo[address] };
        breakpointInfoWindow.show();
        breakpointInfoWindow.exec();
    }
}

void MainWindow::on_action_Disable_all_shown_triggered()
{
    foreach(const auto& address, m_lastBreakpointInfo.keys()){
        bool ok{ };
        auto addressValue{ address.split(",")[0].toULongLong() };
        std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
            TED_DisableBreakCallByAddressFnc(m_client, addressValue), TED_DestroyGenericFnc };
    }
}

void MainWindow::on_action_Enable_all_shown_triggered()
{
    foreach(const auto& address, m_lastBreakpointInfo.keys()){
        auto addressValue{ address.split(",")[0].toULongLong() };
        std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
            TED_EnableBreakCallByAddressFnc(m_client, addressValue), TED_DestroyGenericFnc };
    }
}

void MainWindow::on_action_Disable_custom_triggered()
{
    bool ok{ };
    auto address{ QInputDialog::getText(this, tr("Disable breakpoint"),
                    tr("Address (hex):"), QLineEdit::Normal, "", &ok) };

    if (ok && !address.isEmpty()) {
        auto addressValue{ address.split(",")[0].toULongLong() };
        std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
            TED_DisableBreakCallByAddressFnc(m_client, addressValue), TED_DestroyGenericFnc };
    }
}

void MainWindow::on_action_Enable_custom_triggered()
{
    bool ok{ };
    auto address{ QInputDialog::getText(this, tr("Enable breakpoint"),
                    tr("Address (hex):"), QLineEdit::Normal, "", &ok) };

    if (ok && !address.isEmpty()) {
        auto addressValue{ address.split(",")[0].toULongLong() };
        std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
            TED_EnableBreakCallByAddressFnc(m_client, addressValue), TED_DestroyGenericFnc };
    }
}

void MainWindow::on_action_Clear_triggered()
{
    this->ui->tableWidget_Calls->setRowCount(0);
    m_addressToRow.clear();
}

QPair<QString, uint64_t> MainWindow::getModuleNameAndOffsetForAddress(uint64_t address)
{
    foreach(const auto& addressRange, this->m_moduleAddressRanges.keys()){
        if (address >= addressRange.first && address <= addressRange.second) {
            auto shortName { m_moduleAddressRanges[addressRange]
                             .right(m_moduleAddressRanges[addressRange].length()
                               - (m_moduleAddressRanges[addressRange].lastIndexOf("\\") + 1)) };
            return QPair<QString, uint64_t>{ shortName, address - addressRange.first };
        }
    }

    return QPair<QString, uint64_t>{ "Unknown", 0 };
}

void MainWindow::on_tableWidget_Calls_customContextMenuRequested(const QPoint &pos)
{
    auto menu{ new QMenu(this) };
    auto copyAction{ new QAction("Copy addresses", this) };
    auto removeAction{ new QAction("Remove", this) };

    copyAction->connect(copyAction, &QAction::triggered, this, [pos, copyAction, this]() {
        QTableWidgetItem * selection = this->ui->tableWidget_Calls->itemAt(pos);
        if (selection != nullptr) {
            bool ok{ };
            auto sourceAddressText{ this->ui->tableWidget_Calls->item(selection->row(), 0)->text() };
            auto destinationAddressText{ this->ui->tableWidget_Calls->item(selection->row(), 1)->text() };
            auto sourceAddress{ sourceAddressText.toULongLong(&ok, 16) };
            auto sourceModuleInfo{ getModuleNameAndOffsetForAddress(sourceAddress) };
            auto destinationAddress{ destinationAddressText.toULongLong(&ok, 16) };
            auto destinationModuleInfo{ getModuleNameAndOffsetForAddress(destinationAddress) };
            auto text{
                QString("Source: 0x%1 (%2+0x%3) \t Destination: 0x%4 (%5+0x%6)")
                .arg(sourceAddressText)
                .arg(sourceModuleInfo.first)
                .arg(QString::number(sourceModuleInfo.second, 16))
                .arg(this->ui->tableWidget_Calls->item(selection->row(), 1)->text())
                .arg(destinationModuleInfo.first)
                .arg(QString::number(destinationModuleInfo.second, 16))
            };

            QApplication::clipboard()->setText(text);
        }
    });

    removeAction->connect(removeAction, &QAction::triggered, this, [pos, removeAction, this]() {
        auto selection = this->ui->tableWidget_Calls->itemAt(pos);
        if (selection != nullptr) {
            this->ui->tableWidget_Calls->removeRow(selection->row());
        }
    });

    menu->addAction(copyAction);
    menu->addAction(removeAction);

    menu->popup(this->ui->tableWidget_Calls->viewport()->mapToGlobal(pos));
}

void MainWindow::on_action_About_triggered()
{
    QMessageBox aboutBox{ };

    aboutBox.setTextFormat(Qt::RichText);
    aboutBox.setText("Created by Alex Abramov<br><br>"
      "Blog: <a href='https://www.codereversing.com'>https://www.codereversing.com</a><br><br>"
      "GitHub: <a href='https://github.com/codereversing'>https://github.com/codereversing</a>");
    aboutBox.setStandardButtons(QMessageBox::Ok);
    aboutBox.exec();
}

