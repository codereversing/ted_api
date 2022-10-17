#include "disassembleaddresswindow.h"
#include "ui_disassembleaddresswindow.h"

#include <QByteArray>

#include "errormessagedialog.h"

DisassembleAddressWindow::DisassembleAddressWindow(TED_Client * client, QWidget * parent) :
    QDialog(parent)
    , ui(new Ui::DisassembleAddressWindow)
    , m_client{client}
{
    ui->setupUi(this);
}

DisassembleAddressWindow::~DisassembleAddressWindow()
{
    delete ui;
}

void DisassembleAddressWindow::on_pushButton_Close_clicked()
{
    this->close();
}

void DisassembleAddressWindow::on_pushButton_Disassemble_clicked()
{
    this->ui->tableWidget_Instructions->setRowCount(0);

    bool validAddress{ };
    auto address{ this->ui->lineEdit_Address->text().toULongLong(&validAddress, 16) };
    if (validAddress) {
        std::unique_ptr<TED_DisassembleAddressResponse,
          TED_DestroyDisassembleAddressFncPtr> response{
            TED_DisassembleAddressFnc(m_client, address, 1024), TED_DestroyDisassembleAddressFnc };
        if (response != nullptr) {
            for (size_t i{ 0 }; i < response->instructionsCount; i++) {
                const auto& instruction{ response.get()->instructions[i] };
                this->ui->tableWidget_Instructions->insertRow(this->ui->tableWidget_Instructions->rowCount());

                QString hexBytes{ QByteArray::fromRawData(
                                   reinterpret_cast<const char *>(&instruction->bytes[0]),
                                   instruction->bytesCount).toHex(' ') };


                QString fullInstruction{ instruction->mnemonic };
                fullInstruction += " ";
                fullInstruction += instruction->text;

                this->ui->tableWidget_Instructions->setItem(i, 0,
                  new QTableWidgetItem(QString::number(instruction->address, 16)));
                this->ui->tableWidget_Instructions->setItem(i, 1, new QTableWidgetItem(hexBytes));
                this->ui->tableWidget_Instructions->setItem(i, 2, new QTableWidgetItem(fullInstruction));
            }
        } else {
            ErrorMessageDialog::show("Could not disassmeble address");
        }
    } else {
        ErrorMessageDialog::show("Address is not in a valid format");
    }

    ui->tableWidget_Instructions->resizeColumnsToContents();
    ui->tableWidget_Instructions->horizontalHeader()->stretchLastSection();
}
