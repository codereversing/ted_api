#include "processselectwindow.h"
#include "ui_processselectwindow.h"

#include <memory>

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>

#include "errormessagedialog.h"
#include "numerictablewidgetitem.h"

#include "thirdparty/include/TEDClientBridge.h"

ProcessSelectWindow::ProcessSelectWindow(QString * activeProcessName,
  QString *                                        activeProcessId,
  QWidget *                                        parent) :
  QDialog(parent)
    , ui(new Ui::ProcessSelectWindow)
    , m_activeProcessName{activeProcessName}
    , m_activeProcessId{activeProcessId}
{
    ui->setupUi(this);

    QFileInfo maybeDllPath{ QDir::currentPath() + QDir::separator() + "tedcore.dll" };
    if (maybeDllPath.exists() && maybeDllPath.isFile()) {
        this->ui->lineEdit_Server_dll_path->setText(maybeDllPath.absoluteFilePath());
    }

    refreshActiveProcesses();
}

ProcessSelectWindow::~ProcessSelectWindow()
{
    delete ui;
}

void ProcessSelectWindow::on_pushButton_Close_clicked()
{
    this->close();
}

void ProcessSelectWindow::on_pushButton_Attach_clicked()
{
    attachToProcessAndClose();
}

void ProcessSelectWindow::on_tableWidget_Processes_itemDoubleClicked(QTableWidgetItem * item)
{
    attachToProcessAndClose();
}

void ProcessSelectWindow::on_pushButton_Refresh_clicked()
{
    refreshActiveProcesses();
}

void ProcessSelectWindow::on_pushButton_Find_server_dll_clicked()
{
    auto serverDllPath{ QFileDialog::getOpenFileName(this,
                          tr("Find TED Server Dll"), "", tr("Dll Files (*.dll)")) };

    if (!serverDllPath.isEmpty()) {
        this->ui->lineEdit_Server_dll_path->setText(serverDllPath);
    }
}

void ProcessSelectWindow::refreshActiveProcesses()
{
    this->ui->tableWidget_Processes->setRowCount(0);

    size_t processCount{ };
    auto deleter = [&](auto ** ptr){
          TED_DestroyActiveProcessesInformationFnc(ptr, processCount);
      };
    std::unique_ptr<TED_ProcessInformation *, decltype(deleter)> response{
        TED_GetActiveProcessesInformation(&processCount), deleter };

    int insertIndex{};
    for (size_t i{ 0 }; i < processCount; i++) {
        const auto& process{ response.get()[i] };

        if (m_activeProcessId->isEmpty() || (process->processId != m_activeProcessId->toULong())) {
            this->ui->tableWidget_Processes->insertRow(this->ui->tableWidget_Processes->rowCount());

            this->ui->tableWidget_Processes->setItem(insertIndex, 0, new NumericTableWidgetItem(QString::number(process->processId)));
            this->ui->tableWidget_Processes->setItem(insertIndex, 1, new QTableWidgetItem(process->name));
            this->ui->tableWidget_Processes->setItem(insertIndex, 2, new QTableWidgetItem(process->windowTitle));
            this->ui->tableWidget_Processes->setItem(insertIndex, 3, new QTableWidgetItem(process->path));
            insertIndex++;
        }
    }

    ui->tableWidget_Processes->resizeColumnsToContents();
    ui->tableWidget_Processes->horizontalHeader()->stretchLastSection();
}

void ProcessSelectWindow::attachToProcessAndClose()
{
    auto selection{ this->ui->tableWidget_Processes->selectedItems() };

    if (selection.size() > 0) {
        auto serverDllPath{ this->ui->lineEdit_Server_dll_path->text() };
        if (!serverDllPath.isEmpty()) {
            auto selectedProcessId = selection.at(0)->text();
            auto selectedProcessName = selection.at(1)->text();

            if (!selectedProcessId.isEmpty()) {
                TED_TerminateProcess(m_activeProcessId->toULong());
            }

            auto injected{ TED_InjectIntoProcess(selection.at(0)->text().toULong(),
                             serverDllPath.toStdString().c_str()) };
            if (injected) {
                *m_activeProcessId = selectedProcessId;
                *m_activeProcessName = selectedProcessName;
            } else {
                ErrorMessageDialog::show("Could not inject TED dll to target");
            }

            this->close();
        } else {
            ErrorMessageDialog::show("Server dll path is not valid");
        }
    } else {
        ErrorMessageDialog::show("Process to inject to is not selected");
    }
}
