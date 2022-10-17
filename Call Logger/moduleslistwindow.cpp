#include "moduleslistwindow.h"
#include "ui_moduleslistwindow.h"

#include "errormessagedialog.h"
#include "numerictablewidgetitem.h"

#include "thirdparty/include/TEDClientBridge.h"

ModulesListWindow::ModulesListWindow(TED_Client * client,
  QSet<QString> *                                 activeModules,
  QMap<QPair<uint64_t, uint64_t>, QString> *      moduleAddressRanges,
  QWidget *                                       parent) :
    QDialog(parent)
    , ui(new Ui::ModulesListWindow)
    , m_client{client}
    , m_activeModules{activeModules}
    , m_moduleAddressRanges{moduleAddressRanges}
    , m_moduleNamesMap{}
{
    ui->setupUi(this);

    refreshModules();
}

ModulesListWindow::~ModulesListWindow()
{
    delete ui;
}

void ModulesListWindow::on_pushButton_Close_clicked()
{
    this->close();
}

void ModulesListWindow::refreshModules()
{
    this->ui->tableWidget_Modules->setRowCount(0);

    std::unique_ptr<TED_GetModulesResponse,
      TED_DestroyModulesFncPtr> response{ TED_GetModulesFnc(m_client), TED_DestroyModulesFnc };
    if (response != nullptr) {
        m_moduleAddressRanges->clear();

        for (size_t i{ 0 }; i < response->moduleInfoCount; i++) {
            const auto& module{ response.get()->moduleInfo[i] };
            this->ui->tableWidget_Modules->insertRow(this->ui->tableWidget_Modules->rowCount());

            QString moduleName{ module->name };
            moduleName = moduleName.right(moduleName.length() - (moduleName.lastIndexOf("\\") + 1));
            m_moduleNamesMap[moduleName] = module->name;

            this->ui->tableWidget_Modules->setItem(i, 0, new QTableWidgetItem(moduleName));
            this->ui->tableWidget_Modules->setItem(i, 1,
              new NumericTableWidgetItem(QString::number(module->baseAddress, 16), 16));
            this->ui->tableWidget_Modules->setItem(i, 2,
              new NumericTableWidgetItem(QString::number(module->size, 16), 16));

            QString isActive = m_activeModules->contains(moduleName) ? "Yes" : "No";
            this->ui->tableWidget_Modules->setItem(i, 3, new QTableWidgetItem(isActive));

            auto newKey{ QPair<uint64_t, uint64_t>(
                             module->baseAddress, module->baseAddress + module->size) };
            m_moduleAddressRanges->insert(newKey, QString{ module->name });
        }
    } else {
        ErrorMessageDialog::show("Error getting module list");
    }

    ui->tableWidget_Modules->resizeColumnsToContents();
    ui->tableWidget_Modules->horizontalHeader()->stretchLastSection();
}

void ModulesListWindow::on_pushButton_Log_calls_clicked()
{
    auto selection{ this->ui->tableWidget_Modules->selectedItems() };

    if (selection.size() > 0) {
        auto moduleName{ selection.at(0)->text() };
        if (!m_activeModules->contains(moduleName)) {
            auto fullModuleName{ m_moduleNamesMap[moduleName] };
            std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
                TED_EnableBreakAllCallsInModuleFnc(m_client, fullModuleName.toStdString().c_str()),
                TED_DestroyGenericFnc };
            if (response != nullptr) {
                this->ui->tableWidget_Modules->item(selection.at(0)->row(), 3)->setText("Yes");
                m_activeModules->insert(moduleName);
            }
        }
    }
}

void ModulesListWindow::on_pushButton_Stop_logging_calls_clicked()
{
    auto selection{ this->ui->tableWidget_Modules->selectedItems() };

    if (selection.size() > 0) {
        auto moduleName{ selection.at(0)->text() };
        if (m_activeModules->contains(moduleName)) {
            auto fullModuleName{ m_moduleNamesMap[moduleName] };
            std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
                TED_DisableBreakAllCallsInModuleFnc(m_client, fullModuleName.toStdString().c_str()),
                TED_DestroyGenericFnc };
            if (response != nullptr) {
                this->ui->tableWidget_Modules->item(selection.at(0)->row(), 3)->setText("No");
                m_activeModules->remove(moduleName);
            }
        }
    }
}
